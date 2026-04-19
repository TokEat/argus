package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	pb "github.com/user/dddd-proto/go/scan"
)

// ============================================================================
// 多优先级 Redis Stream 任务队列
//
// 架构设计:
//   - 三级优先级 Stream: dddd:tasks:urgent / dddd:tasks:normal / dddd:tasks:low
//   - 回收任务走 urgent 级别，确保死亡节点的任务被优先重新执行
//   - PopTask 按优先级降序依次尝试 XREADGROUP，高优先级先消费
//   - 内存队列 fallback 同步支持优先级排序
//   - 支持队列深度监控 (QueueDepth)
// ============================================================================

const (
	PriorityUrgent = 0 // 回收/紧急任务
	PriorityNormal = 1 // 普通任务（默认）
	PriorityLow    = 2 // 低优先级/后台扫描

	consumerGroup = "dddd_agents"
)

// priorityStreams 按优先级从高到低的 Stream Key
var priorityStreams = []string{
	"dddd:tasks:urgent", // P0: 回收任务、紧急任务
	"dddd:tasks:normal", // P1: 普通任务
	"dddd:tasks:low",    // P2: 低优先级
}

// TaskQueue 封装基于 Redis 的多优先级任务队列分配器
type TaskQueue struct {
	client *redis.Client
	mem    *memoryQueue
	mode   string
}

// NewTaskQueue 初始化队列（Redis 模式或内存 Fallback）
func NewTaskQueue(addr string, password string, db int) *TaskQueue {
	queue := &TaskQueue{}

	addr = strings.TrimSpace(addr)
	if addr == "" {
		queue.mode = "memory"
		queue.mem = newMemoryQueue()
		return queue
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("redis unavailable at %s, falling back to in-memory queue: %v", addr, err)
		_ = rdb.Close()
		queue.mode = "memory"
		queue.mem = newMemoryQueue()
		return queue
	}

	queue.client = rdb
	queue.mode = "redis"

	// 为每个优先级 Stream 创建消费组
	for _, streamKey := range priorityStreams {
		err := rdb.XGroupCreateMkStream(context.Background(), streamKey, consumerGroup, "$").Err()
		if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
			log.Printf("Warning: failed to create consumer group for %s: %v", streamKey, err)
		}
	}

	// 兼容旧版：如果旧的 dddd:tasks:pending 中还有残余消息，迁移到 normal 队列
	go queue.migrateOldStream()

	// 启动死信回收守护
	go queue.daemonSalvage()

	log.Printf("[TaskQueue] Initialized with %d priority streams", len(priorityStreams))
	return queue
}

func (q *TaskQueue) Mode() string {
	if q.mode == "" {
		return "memory"
	}
	return q.mode
}

// ============================================================================
// Push 入队
// ============================================================================

// PushTask 将任务按优先级路由到对应 Stream
func (q *TaskQueue) PushTask(ctx context.Context, task *pb.Task) error {
	if q.client == nil {
		q.mem.push(task, int(task.Priority))
		return nil
	}

	streamKey := priorityToStream(int(task.Priority))

	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("task marshal error: %w", err)
	}

	return q.client.XAdd(ctx, &redis.XAddArgs{
		Stream: streamKey,
		Values: map[string]interface{}{"payload": data},
	}).Err()
}

// PushTaskToFront 将恢复/抢救的任务压入最高优先级 urgent 队列
// 与 PushTask 不同：无论原始优先级是什么，都进 urgent 确保优先执行
func (q *TaskQueue) PushTaskToFront(ctx context.Context, task *pb.Task) error {
	if q.client == nil {
		q.mem.push(task, PriorityUrgent) // 内存模式：插到队首
		return nil
	}

	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("task marshal error: %w", err)
	}

	// 强制写入 urgent 队列
	return q.client.XAdd(ctx, &redis.XAddArgs{
		Stream: priorityStreams[PriorityUrgent],
		Values: map[string]interface{}{"payload": data},
	}).Err()
}

// ============================================================================
// Pop 出队 — 多优先级降序消费
// ============================================================================

// PopTask 按优先级从高到低依次尝试读取任务
// 先尝试 urgent，再 normal，最后 low；每级不阻塞（非阻塞轮询）
// 只有全部为空时才阻塞等待 1s（在最低优先级上）
func (q *TaskQueue) PopTask(ctx context.Context, agentID string) (*pb.Task, string, error) {
	if q.client == nil {
		t, err := q.mem.pop(ctx, time.Second)
		return t, "", err
	}

	// 依次尝试高优先级 Stream（非阻塞）
	for i, streamKey := range priorityStreams {
		blockTime := time.Duration(0) // 非阻塞
		if i == len(priorityStreams)-1 {
			blockTime = 1 * time.Second // 最低优先级阻塞等待
		}

		result, err := q.client.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    consumerGroup,
			Consumer: agentID,
			Streams:  []string{streamKey, ">"},
			Count:    1,
			Block:    blockTime,
		}).Result()

		if err == redis.Nil || len(result) == 0 || len(result[0].Messages) == 0 {
			continue // 此优先级为空，尝试下一级
		}
		if err != nil {
			return nil, "", fmt.Errorf("XReadGroup error on %s: %w", streamKey, err)
		}

		msg := result[0].Messages[0]
		payloadStr, ok := msg.Values["payload"].(string)
		if !ok {
			// 格式错误，ACK 掉避免反复消费
			q.client.XAck(ctx, streamKey, consumerGroup, msg.ID)
			continue
		}

		var task pb.Task
		if err := json.Unmarshal([]byte(payloadStr), &task); err != nil {
			q.client.XAck(ctx, streamKey, consumerGroup, msg.ID)
			continue
		}

		// msgID 编码为 "streamKey|msgID" 以便 AckTask 时知道回哪个 Stream
		compositeID := streamKey + "|" + msg.ID
		return &task, compositeID, nil
	}

	return nil, "", nil // 全部为空
}

// ============================================================================
// Ack 确认
// ============================================================================

// AckTask 确认任务完成，从 Pending 列表中移除
// compositeID 格式: "streamKey|msgID"
func (q *TaskQueue) AckTask(ctx context.Context, compositeID string) error {
	if q.client == nil || compositeID == "" {
		return nil
	}

	parts := strings.SplitN(compositeID, "|", 2)
	if len(parts) != 2 {
		// 兼容旧格式（不带 stream 前缀的纯 msgID）
		// 尝试在所有 stream 中 ACK
		for _, streamKey := range priorityStreams {
			_ = q.client.XAck(ctx, streamKey, consumerGroup, compositeID).Err()
		}
		return nil
	}

	streamKey, msgID := parts[0], parts[1]
	return q.client.XAck(ctx, streamKey, consumerGroup, msgID).Err()
}

// ============================================================================
// 队列监控
// ============================================================================

// QueueDepth 返回各优先级队列的待处理消息数
func (q *TaskQueue) QueueDepth(ctx context.Context) map[string]int64 {
	depths := make(map[string]int64)
	if q.client == nil {
		q.mem.mu.Lock()
		depths["memory"] = int64(len(q.mem.tasks))
		q.mem.mu.Unlock()
		return depths
	}

	for _, streamKey := range priorityStreams {
		info, err := q.client.XInfoStream(ctx, streamKey).Result()
		if err == nil {
			depths[streamKey] = info.Length
		}
	}
	return depths
}

// PendingCount 返回各优先级队列中仍在处理中（未 ACK）的消息数
func (q *TaskQueue) PendingCount(ctx context.Context) map[string]int64 {
	counts := make(map[string]int64)
	if q.client == nil {
		return counts
	}

	for _, streamKey := range priorityStreams {
		info, err := q.client.XPending(ctx, streamKey, consumerGroup).Result()
		if err == nil {
			counts[streamKey] = info.Count
		}
	}
	return counts
}

// ============================================================================
// 死信回收守护协程
// ============================================================================

// daemonSalvage 定期审查所有 Stream 的 Pending 队列，抢救孤儿任务
func (q *TaskQueue) daemonSalvage() {
	if q.mode != "redis" {
		return
	}
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()
		totalRecovered := 0

		for _, streamKey := range priorityStreams {
			pendings, err := q.client.XPendingExt(ctx, &redis.XPendingExtArgs{
				Stream: streamKey,
				Group:  consumerGroup,
				Start:  "-",
				End:    "+",
				Count:  100,
				Idle:   30 * time.Minute, // 从 1h 缩短到 30min，更激进的回收
			}).Result()

			if err != nil || len(pendings) == 0 {
				continue
			}

			for _, p := range pendings {
				msgs, claimErr := q.client.XClaim(ctx, &redis.XClaimArgs{
					Stream:   streamKey,
					Group:    consumerGroup,
					MinIdle:  30 * time.Minute,
					Messages: []string{p.ID},
					Consumer: "daemon_salvager",
				}).Result()

				if claimErr != nil || len(msgs) == 0 {
					continue
				}

				msg := msgs[0]
				// ACK 掉旧消息
				q.client.XAck(ctx, streamKey, consumerGroup, msg.ID)
				// 重新投入 urgent 队列（回收任务优先执行）
				q.client.XAdd(ctx, &redis.XAddArgs{
					Stream: priorityStreams[PriorityUrgent],
					Values: msg.Values,
				})
				totalRecovered++
				log.Printf("[Dead-Letter] Recovered abandoned msg %s from %s (Idle %v) → urgent queue",
					msg.ID, streamKey, p.Idle)
			}
		}

		if totalRecovered > 0 {
			log.Printf("[Dead-Letter] Salvage cycle: recovered %d tasks", totalRecovered)
		}
	}
}

// migrateOldStream 将旧 Stream (dddd:tasks:pending) 的残留消息迁移到新的 normal 队列
func (q *TaskQueue) migrateOldStream() {
	if q.client == nil {
		return
	}
	ctx := context.Background()
	oldKey := "dddd:tasks:pending"

	// 检查旧 Stream 是否存在
	exists, err := q.client.Exists(ctx, oldKey).Result()
	if err != nil || exists == 0 {
		return
	}

	// 读取所有未消费的消息
	msgs, err := q.client.XRange(ctx, oldKey, "-", "+").Result()
	if err != nil || len(msgs) == 0 {
		return
	}

	migrated := 0
	for _, msg := range msgs {
		q.client.XAdd(ctx, &redis.XAddArgs{
			Stream: priorityStreams[PriorityNormal],
			Values: msg.Values,
		})
		migrated++
	}

	if migrated > 0 {
		log.Printf("[Migration] Moved %d tasks from old stream '%s' to '%s'", migrated, oldKey, priorityStreams[PriorityNormal])
		// 删除旧 Stream
		q.client.Del(ctx, oldKey)
	}
}

// ============================================================================
// 辅助函数
// ============================================================================

func priorityToStream(priority int) string {
	switch {
	case priority <= PriorityUrgent:
		return priorityStreams[PriorityUrgent]
	case priority >= PriorityLow:
		return priorityStreams[PriorityLow]
	default:
		return priorityStreams[PriorityNormal]
	}
}

// ============================================================================
// 内存队列 Fallback（支持优先级排序）
// ============================================================================

type memoryTask struct {
	task     *pb.Task
	priority int
}

type memoryQueue struct {
	mu     sync.Mutex
	tasks  []memoryTask
	notify chan struct{}
}

func newMemoryQueue() *memoryQueue {
	return &memoryQueue{
		notify: make(chan struct{}, 1),
	}
}

// push 按优先级插入，越小优先级越高
func (q *memoryQueue) push(task *pb.Task, priority int) {
	q.mu.Lock()
	// 找到第一个优先级比当前低的位置，插入其前面
	inserted := false
	for i, t := range q.tasks {
		if t.priority > priority {
			// 在位置 i 处插入
			q.tasks = append(q.tasks[:i+1], q.tasks[i:]...)
			q.tasks[i] = memoryTask{task: task, priority: priority}
			inserted = true
			break
		}
	}
	if !inserted {
		q.tasks = append(q.tasks, memoryTask{task: task, priority: priority})
	}
	q.mu.Unlock()
	q.signal()
}

func (q *memoryQueue) pop(ctx context.Context, wait time.Duration) (*pb.Task, error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()

	for {
		q.mu.Lock()
		if len(q.tasks) > 0 {
			task := q.tasks[0].task
			q.tasks = q.tasks[1:]
			q.mu.Unlock()
			return task, nil
		}
		q.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, nil
		case <-q.notify:
		}
	}
}

func (q *memoryQueue) signal() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

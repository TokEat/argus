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

// TaskQueue 封装基于 Redis 的任务队列分配器
type TaskQueue struct {
	client   *redis.Client
	queueKey string
	mem      *memoryQueue
	mode     string
}

type memoryQueue struct {
	mu     sync.Mutex
	tasks  []*pb.Task
	notify chan struct{}
}

// NewTaskQueue 初始化基于 Redis List 的队列
func NewTaskQueue(addr string, password string, db int) *TaskQueue {
	queue := &TaskQueue{
		queueKey: "dddd:tasks:pending",
	}

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

	// 初始化 Stream 和消费组 (如果不存在则创建)
	err := rdb.XGroupCreateMkStream(context.Background(), queue.queueKey, "dddd_agents", "$").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		log.Printf("Warning: failed to create consumer group: %v", err)
	}

	go queue.daemonSalvage()

	return queue
}

// daemonSalvage 死神协程：定期审查 Redis Pending 队列抓取孤魂
func (q *TaskQueue) daemonSalvage() {
	if q.mode != "redis" {
		return
	}
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ctx := context.Background()
		// 寻找 Idle 时间超过 1 小时的孤魂
		pendings, err := q.client.XPendingExt(ctx, &redis.XPendingExtArgs{
			Stream: q.queueKey,
			Group:  "dddd_agents",
			Start:  "-",
			End:    "+",
			Count:  100,
			Idle:   1 * time.Hour,
		}).Result()

		if err == nil && len(pendings) > 0 {
			for _, p := range pendings {
				// 利用 XCLAIM 争夺该消息所属权
				msgs, claimErr := q.client.XClaim(ctx, &redis.XClaimArgs{
					Stream:   q.queueKey,
					Group:    "dddd_agents",
					MinIdle:  1 * time.Hour,
					Messages: []string{p.ID},
					Consumer: "daemon_salvager", // 控制塔自建的清道夫名义
				}).Result()

				if claimErr == nil && len(msgs) > 0 {
					msg := msgs[0]
					// 抹杀旧记录
					q.client.XAck(ctx, q.queueKey, "dddd_agents", msg.ID)
					// 将原汁原味的任务负载重新投入流中
					q.client.XAdd(ctx, &redis.XAddArgs{
						Stream: q.queueKey,
						Values: msg.Values,
					})
					log.Printf("[Dead-Letter] Recovering abandoned message %s (Idle %v). Re-queued as new msg.", msg.ID, p.Idle)
				}
			}
		}
	}
}

func (q *TaskQueue) Mode() string {
	if q.mode == "" {
		return "memory"
	}
	return q.mode
}

// PushTask 将一个扫描任务压入 Stream 尾部
func (q *TaskQueue) PushTask(ctx context.Context, task *pb.Task) error {
	if q.client == nil {
		q.mem.pushBack(task)
		return nil
	}

	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("task marshal error: %w", err)
	}

	return q.client.XAdd(ctx, &redis.XAddArgs{
		Stream: q.queueKey,
		Values: map[string]interface{}{"payload": data},
	}).Err()
}

// PushTaskToFront (对于 Stream 我们放弃插队，直接 XADD 尾部或者依赖调度中控分配引擎)
func (q *TaskQueue) PushTaskToFront(ctx context.Context, task *pb.Task) error {
	return q.PushTask(ctx, task)
}

// PopTask 从 Stream 中通过消费组按需读取任务
func (q *TaskQueue) PopTask(ctx context.Context, agentID string) (*pb.Task, string, error) {
	if q.client == nil {
		t, err := q.mem.pop(ctx, time.Second)
		return t, "", err
	}

	// 等待 1 秒，如果没有拿到则返回空
	result, err := q.client.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    "dddd_agents",
		Consumer: agentID,
		Streams:  []string{q.queueKey, ">"},
		Count:    1,
		Block:    1 * time.Second,
	}).Result()

	if err == redis.Nil || len(result) == 0 || len(result[0].Messages) == 0 {
		return nil, "", nil // 队列为空
	} else if err != nil {
		return nil, "", fmt.Errorf("XReadGroup error: %w", err)
	}

	msg := result[0].Messages[0]
	payloadStr, ok := msg.Values["payload"].(string)
	if !ok {
		return nil, "", fmt.Errorf("invalid payload format in stream")
	}

	var task pb.Task
	if err := json.Unmarshal([]byte(payloadStr), &task); err != nil {
		return nil, "", fmt.Errorf("task unmarshal error: %w", err)
	}

	return &task, msg.ID, nil
}

// AckTask 确认某个 Stream 的消息被成功处理，将其从 Pending 列表抹除
func (q *TaskQueue) AckTask(ctx context.Context, msgID string) error {
	if q.client == nil || msgID == "" {
		return nil
	}
	return q.client.XAck(ctx, q.queueKey, "dddd_agents", msgID).Err()
}

func newMemoryQueue() *memoryQueue {
	return &memoryQueue{
		notify: make(chan struct{}, 1),
	}
}

func (q *memoryQueue) pushBack(task *pb.Task) {
	q.mu.Lock()
	q.tasks = append(q.tasks, task)
	q.mu.Unlock()
	q.signal()
}

func (q *memoryQueue) pushFront(task *pb.Task) {
	q.mu.Lock()
	q.tasks = append([]*pb.Task{task}, q.tasks...)
	q.mu.Unlock()
	q.signal()
}

func (q *memoryQueue) pop(ctx context.Context, wait time.Duration) (*pb.Task, error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()

	for {
		q.mu.Lock()
		if len(q.tasks) > 0 {
			task := q.tasks[0]
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

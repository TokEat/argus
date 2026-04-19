package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	pb "github.com/user/dddd-proto/go/scan"
)

// ============================================================================
// 多优先级 RabbitMQ 任务队列
//
// 架构设计:
//   - 三级优先级队列: dddd.tasks.urgent / dddd.tasks.normal / dddd.tasks.low
//   - 使用 basic.get (pull 模式) 按优先级降序消费，高优先级先消费
//   - 手动 ACK 保证任务可靠投递（Server 崩溃时 RabbitMQ 自动 requeue）
//   - 内存队列 fallback 用于无 RabbitMQ 的开发环境
//   - 支持队列深度监控 (QueueDepth)
// ============================================================================

const (
	PriorityUrgent = 0 // 回收/紧急任务
	PriorityNormal = 1 // 普通任务（默认）
	PriorityLow    = 2 // 低优先级/后台扫描
)

// priorityQueues 按优先级从高到低的 Queue 名
var priorityQueues = []string{
	"dddd.tasks.urgent", // P0: 回收任务、紧急任务
	"dddd.tasks.normal", // P1: 普通任务
	"dddd.tasks.low",    // P2: 低优先级
}

// pendingDelivery 记录一次未确认的消息投递
type pendingDelivery struct {
	tag       uint64
	queueName string
	agentID   string
	claimedAt time.Time
}

// TaskQueue 封装基于 RabbitMQ 的多优先级任务队列
type TaskQueue struct {
	conn *amqp.Connection
	ch   *amqp.Channel
	chMu sync.Mutex // 保护 channel 操作的并发安全
	mem  *memoryQueue
	mode string

	// pendingAcks 跟踪未确认的投递: compositeID → *pendingDelivery
	pendingAcks sync.Map
}

// NewTaskQueue 初始化队列（RabbitMQ 模式或内存 Fallback）
func NewTaskQueue(amqpURL string) *TaskQueue {
	queue := &TaskQueue{}

	amqpURL = strings.TrimSpace(amqpURL)
	if amqpURL == "" {
		queue.mode = "memory"
		queue.mem = newMemoryQueue()
		return queue
	}

	conn, err := amqp.Dial(amqpURL)
	if err != nil {
		log.Printf("RabbitMQ unavailable at %s, falling back to in-memory queue: %v", amqpURL, err)
		queue.mode = "memory"
		queue.mem = newMemoryQueue()
		return queue
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		log.Printf("Failed to open RabbitMQ channel, falling back to in-memory queue: %v", err)
		queue.mode = "memory"
		queue.mem = newMemoryQueue()
		return queue
	}

	queue.conn = conn
	queue.ch = ch
	queue.mode = "rabbitmq"

	// 声明三级优先级队列（持久化）
	for _, queueName := range priorityQueues {
		_, err := ch.QueueDeclare(
			queueName,
			true,  // durable — 队列持久化
			false, // auto-delete
			false, // exclusive
			false, // no-wait
			nil,
		)
		if err != nil {
			log.Printf("Warning: failed to declare queue %s: %v", queueName, err)
		}
	}

	// 启动超时投递回收守护
	go queue.staleSalvage()

	log.Printf("[TaskQueue] RabbitMQ initialized with %d priority queues", len(priorityQueues))
	return queue
}

func (q *TaskQueue) Mode() string {
	if q.mode == "" {
		return "memory"
	}
	return q.mode
}

// Close 关闭 RabbitMQ 连接
func (q *TaskQueue) Close() {
	if q.ch != nil {
		q.ch.Close()
	}
	if q.conn != nil {
		q.conn.Close()
	}
}

// ============================================================================
// Push 入队
// ============================================================================

// PushTask 将任务按优先级路由到对应 Queue
func (q *TaskQueue) PushTask(ctx context.Context, task *pb.Task) error {
	if q.conn == nil {
		q.mem.push(task, int(task.Priority))
		return nil
	}

	queueName := priorityToQueue(int(task.Priority))
	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("task marshal error: %w", err)
	}

	q.chMu.Lock()
	defer q.chMu.Unlock()

	return q.ch.PublishWithContext(ctx, "", queueName, false, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent, // 消息持久化
		Body:         data,
	})
}

// PushTaskToFront 将恢复/抢救的任务压入最高优先级 urgent 队列
func (q *TaskQueue) PushTaskToFront(ctx context.Context, task *pb.Task) error {
	if q.conn == nil {
		q.mem.push(task, PriorityUrgent)
		return nil
	}

	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("task marshal error: %w", err)
	}

	q.chMu.Lock()
	defer q.chMu.Unlock()

	return q.ch.PublishWithContext(ctx, "", priorityQueues[PriorityUrgent], false, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		Body:         data,
	})
}

// ============================================================================
// Pop 出队 — 多优先级降序消费
// ============================================================================

// TryPopTask 完全非阻塞：按优先级从高到低依次 basic.get，立即返回
func (q *TaskQueue) TryPopTask(ctx context.Context, agentID string) (*pb.Task, string, error) {
	if q.conn == nil {
		q.mem.mu.Lock()
		if len(q.mem.tasks) > 0 {
			task := q.mem.tasks[0].task
			q.mem.tasks = q.mem.tasks[1:]
			q.mem.mu.Unlock()
			return task, "", nil
		}
		q.mem.mu.Unlock()
		return nil, "", nil
	}

	q.chMu.Lock()
	defer q.chMu.Unlock()

	for _, queueName := range priorityQueues {
		msg, ok, err := q.ch.Get(queueName, false) // autoAck=false, 手动确认
		if err != nil {
			return nil, "", fmt.Errorf("RabbitMQ Get error on %s: %w", queueName, err)
		}
		if !ok {
			continue // 此队列为空，尝试下一级
		}

		var task pb.Task
		if err := json.Unmarshal(msg.Body, &task); err != nil {
			// 格式错误，直接 ACK 掉避免反复消费
			_ = q.ch.Ack(msg.DeliveryTag, false)
			log.Printf("[TaskQueue] Discarded malformed message from %s: %v", queueName, err)
			continue
		}

		// 生成 compositeID 并记录投递信息
		compositeID := fmt.Sprintf("%s|%d", queueName, msg.DeliveryTag)
		q.pendingAcks.Store(compositeID, &pendingDelivery{
			tag:       msg.DeliveryTag,
			queueName: queueName,
			agentID:   agentID,
			claimedAt: time.Now(),
		})

		return &task, compositeID, nil
	}

	return nil, "", nil // 全部为空
}

// PopTask 阻塞版本：先尝试立即获取，失败后等待 500ms 重试一次
func (q *TaskQueue) PopTask(ctx context.Context, agentID string) (*pb.Task, string, error) {
	if q.conn == nil {
		t, err := q.mem.pop(ctx, time.Second)
		return t, "", err
	}

	// 先尝试立即获取
	task, id, err := q.TryPopTask(ctx, agentID)
	if err != nil || task != nil {
		return task, id, err
	}

	// 短暂等待后重试
	time.Sleep(500 * time.Millisecond)
	return q.TryPopTask(ctx, agentID)
}

// ============================================================================
// Ack / Nack 确认
// ============================================================================

// AckTask 确认任务完成
func (q *TaskQueue) AckTask(ctx context.Context, compositeID string) error {
	if q.conn == nil || compositeID == "" {
		return nil
	}

	val, ok := q.pendingAcks.LoadAndDelete(compositeID)
	if !ok {
		return nil // 已确认或未知
	}

	pd := val.(*pendingDelivery)
	q.chMu.Lock()
	defer q.chMu.Unlock()

	return q.ch.Ack(pd.tag, false)
}

// NackTask 拒绝并重新入队（用于标签不匹配退回）
func (q *TaskQueue) NackTask(ctx context.Context, compositeID string) error {
	if q.conn == nil || compositeID == "" {
		return nil
	}

	val, ok := q.pendingAcks.LoadAndDelete(compositeID)
	if !ok {
		return nil
	}

	pd := val.(*pendingDelivery)
	q.chMu.Lock()
	defer q.chMu.Unlock()

	return q.ch.Nack(pd.tag, false, true) // requeue=true
}

// ============================================================================
// 队列监控
// ============================================================================

// QueueDepth 返回各优先级队列中可消费的消息数（Ready 状态）
func (q *TaskQueue) QueueDepth(ctx context.Context) map[string]int64 {
	depths := make(map[string]int64)
	if q.conn == nil {
		q.mem.mu.Lock()
		depths["memory"] = int64(len(q.mem.tasks))
		q.mem.mu.Unlock()
		return depths
	}

	q.chMu.Lock()
	defer q.chMu.Unlock()

	for _, queueName := range priorityQueues {
		info, err := q.ch.QueueInspect(queueName)
		if err == nil {
			// QueueInspect.Messages = Ready + Unacked
			// 但我们只关心 Ready（可被消费的数量）
			depths[queueName] = int64(info.Messages)
		}
	}
	return depths
}

// PendingCount 返回各队列中正在处理中（未 ACK）的消息数
func (q *TaskQueue) PendingCount(ctx context.Context) map[string]int64 {
	counts := make(map[string]int64)
	q.pendingAcks.Range(func(key, value any) bool {
		pd := value.(*pendingDelivery)
		counts[pd.queueName]++
		return true
	})
	return counts
}

// ============================================================================
// 超时投递回收守护
// ============================================================================

// staleSalvage 定期检查长时间未 ACK 的投递并 Nack 重新入队
func (q *TaskQueue) staleSalvage() {
	if q.mode != "rabbitmq" {
		return
	}

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		staleThreshold := time.Now().Add(-30 * time.Minute)
		recovered := 0

		q.pendingAcks.Range(func(key, value any) bool {
			pd := value.(*pendingDelivery)
			if pd.claimedAt.Before(staleThreshold) {
				compositeID := key.(string)
				log.Printf("[Stale-Salvage] Nacking stale delivery %s (agent=%s, age=%v)",
					compositeID, pd.agentID, time.Since(pd.claimedAt))
				_ = q.NackTask(context.Background(), compositeID)
				recovered++
			}
			return true
		})

		if recovered > 0 {
			log.Printf("[Stale-Salvage] Recovered %d stale deliveries", recovered)
		}
	}
}

// ============================================================================
// 辅助函数
// ============================================================================

func priorityToQueue(priority int) string {
	switch {
	case priority <= PriorityUrgent:
		return priorityQueues[PriorityUrgent]
	case priority >= PriorityLow:
		return priorityQueues[PriorityLow]
	default:
		return priorityQueues[PriorityNormal]
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
	inserted := false
	for i, t := range q.tasks {
		if t.priority > priority {
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

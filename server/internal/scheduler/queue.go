package scheduler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
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
//   - 仅未配置 AMQP URL 时使用内存队列；显式 RabbitMQ 模式故障时保持失败可见
//   - 支持队列深度监控 (QueueDepth)
// ============================================================================

const (
	PriorityUrgent = 0 // 回收/紧急任务
	PriorityNormal = 1 // 普通任务（默认）
	PriorityLow    = 2 // 低优先级/后台扫描

	rabbitMQHeartbeat   = 10 * time.Second
	rabbitMQDialTimeout = 5 * time.Second
)

var errTaskQueueClosed = errors.New("task queue is closed")

var queueEpochCounter atomic.Uint64

// priorityQueues 按优先级从高到低的 Queue 名
var priorityQueues = []string{
	"dddd.tasks.urgent", // P0: 回收任务、紧急任务
	"dddd.tasks.normal", // P1: 普通任务
	"dddd.tasks.low",    // P2: 低优先级
}

// pendingDelivery 记录一次未确认的消息投递
type pendingDelivery struct {
	tag        uint64
	queueName  string
	agentID    string
	claimedAt  time.Time
	generation uint64
}

// TaskQueue 封装基于 RabbitMQ 的多优先级任务队列
type TaskQueue struct {
	conn       *amqp.Connection
	ch         *amqp.Channel
	chMu       sync.Mutex // 保护 channel 操作的并发安全
	amqpURL    string     // 保留连接地址用于自动重连
	mem        *memoryQueue
	mode       string
	epoch      string
	closed     bool
	unhealthy  bool
	generation uint64
	done       chan struct{}
	closeOnce  sync.Once

	// pendingAcks 跟踪未确认的投递: compositeID → *pendingDelivery
	pendingAcks sync.Map
}

// NewTaskQueue 根据 AMQP URL 是否配置初始化 RabbitMQ 或内存队列。
func NewTaskQueue(amqpURL string) *TaskQueue {
	amqpURL = strings.TrimSpace(amqpURL)
	epoch := newQueueEpoch()
	if amqpURL == "" {
		return &TaskQueue{mode: "memory", epoch: epoch, mem: newMemoryQueue(), done: make(chan struct{})}
	}

	queue := &TaskQueue{mode: "rabbitmq", epoch: epoch, amqpURL: amqpURL, unhealthy: true, done: make(chan struct{})}
	queue.chMu.Lock()
	err := queue.connectLocked()
	queue.chMu.Unlock()
	if err != nil {
		log.Printf("[TaskQueue] RabbitMQ unavailable at startup; queue remains in rabbitmq mode and will retry: %v", err)
	} else {
		log.Printf("[TaskQueue] RabbitMQ initialized with %d priority queues", len(priorityQueues))
	}

	// 启动超时投递回收守护
	go queue.staleSalvage()
	return queue
}

func (q *TaskQueue) Mode() string {
	if q.mode == "" {
		return "memory"
	}
	return q.mode
}

// RecoveryToken identifies one queue process and connection generation.
// It changes after a RabbitMQ reconnect and across server restarts.
func (q *TaskQueue) RecoveryToken() string {
	if q == nil {
		return ""
	}
	q.chMu.Lock()
	defer q.chMu.Unlock()
	return fmt.Sprintf("%s|%d", q.epoch, q.generation)
}

// Close 关闭 RabbitMQ 连接
func (q *TaskQueue) Close() {
	q.chMu.Lock()
	defer q.chMu.Unlock()
	q.closed = true
	q.closeOnce.Do(func() { close(q.done) })
	q.invalidatePendingLocked()
	if q.ch != nil {
		_ = q.ch.Close()
		q.ch = nil
	}
	if q.conn != nil {
		_ = q.conn.Close()
		q.conn = nil
	}
}

// ForceRecover 在 NotifyClose/heartbeat 标记连接失效后执行一次有界重连。
// 显式 RabbitMQ 模式不会在故障时切换到内存队列。
func (q *TaskQueue) ForceRecover() (bool, error) {
	if q.mode == "memory" {
		return false, nil
	}

	q.chMu.Lock()
	defer q.chMu.Unlock()
	if q.connectionHealthyLocked() {
		return false, nil
	}
	if err := q.connectLocked(); err != nil {
		return false, err
	}
	return true, nil
}

// ensureChannel 在操作前检测 Channel 健康状态并按需重建。
// 调用方必须已持有 chMu 锁。
func (q *TaskQueue) ensureChannel() error {
	if q.mode == "memory" {
		return nil
	}
	if q.connectionHealthyLocked() {
		return nil
	}
	return q.connectLocked()
}

func (q *TaskQueue) connectionHealthyLocked() bool {
	return !q.closed && !q.unhealthy && q.conn != nil && q.ch != nil && !q.conn.IsClosed() && !q.ch.IsClosed()
}

func (q *TaskQueue) connectLocked() error {
	if q.closed {
		return errTaskQueueClosed
	}

	q.unhealthy = true
	q.invalidatePendingLocked()
	if q.ch != nil {
		_ = q.ch.Close()
		q.ch = nil
	}
	if q.conn != nil {
		_ = q.conn.Close()
		q.conn = nil
	}

	conn, err := amqp.DialConfig(q.amqpURL, amqp.Config{
		Heartbeat: rabbitMQHeartbeat,
		Dial:      amqp.DefaultDial(rabbitMQDialTimeout),
	})
	if err != nil {
		return fmt.Errorf("RabbitMQ connect failed: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("RabbitMQ channel open failed: %w", err)
	}
	for _, queueName := range priorityQueues {
		if _, err := ch.QueueDeclare(queueName, true, false, false, false, nil); err != nil {
			_ = ch.Close()
			_ = conn.Close()
			return fmt.Errorf("RabbitMQ queue declare %s failed: %w", queueName, err)
		}
	}
	if err := ch.Confirm(false); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return fmt.Errorf("RabbitMQ publisher confirm setup failed: %w", err)
	}

	q.generation++
	q.conn = conn
	q.ch = ch
	q.unhealthy = false
	q.watchConnection(q.generation, conn, ch)
	return nil
}

func (q *TaskQueue) watchConnection(generation uint64, conn *amqp.Connection, ch *amqp.Channel) {
	connClosed := conn.NotifyClose(make(chan *amqp.Error, 1))
	channelClosed := ch.NotifyClose(make(chan *amqp.Error, 1))
	go func() {
		var closeErr *amqp.Error
		select {
		case closeErr = <-connClosed:
		case closeErr = <-channelClosed:
		}

		q.chMu.Lock()
		if q.closed || q.generation != generation || q.conn != conn {
			q.chMu.Unlock()
			return
		}
		q.unhealthy = true
		q.chMu.Unlock()
		if closeErr != nil {
			log.Printf("[TaskQueue] RabbitMQ generation %d closed: %v", generation, closeErr)
		} else {
			log.Printf("[TaskQueue] RabbitMQ generation %d closed", generation)
		}
		q.reconnectLoop(generation)
	}()
}

func (q *TaskQueue) reconnectLoop(closedGeneration uint64) {
	backoff := time.Second
	for {
		select {
		case <-q.done:
			return
		default:
		}

		recovered, err := q.ForceRecover()
		if err == nil {
			if recovered {
				log.Printf("[TaskQueue] RabbitMQ generation %d recovered as generation %d", closedGeneration, q.currentGeneration())
			}
			return
		}
		if errors.Is(err, errTaskQueueClosed) {
			return
		}
		log.Printf("[TaskQueue] RabbitMQ reconnect retry failed: %v", err)

		timer := time.NewTimer(backoff)
		select {
		case <-q.done:
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 5*time.Second {
			backoff *= 2
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
		}
	}
}

func (q *TaskQueue) currentGeneration() uint64 {
	q.chMu.Lock()
	defer q.chMu.Unlock()
	return q.generation
}

func (q *TaskQueue) invalidatePendingLocked() {
	q.pendingAcks.Clear()
}

// ============================================================================
// Push 入队
// ============================================================================

// PushTask 将任务按优先级路由到对应 Queue
func (q *TaskQueue) PushTask(ctx context.Context, task *pb.Task) error {
	if q.mode == "memory" {
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

	if err := q.ensureChannel(); err != nil {
		return err
	}

	err = q.publishConfirmedLocked(ctx, queueName, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent, // 消息持久化
		Body:         data,
	})
	if err != nil {
		q.unhealthy = true
	}
	return err
}

// PushTaskToFront 将恢复/抢救的任务压入最高优先级 urgent 队列
func (q *TaskQueue) PushTaskToFront(ctx context.Context, task *pb.Task) error {
	if q.mode == "memory" {
		q.mem.push(task, PriorityUrgent)
		return nil
	}

	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("task marshal error: %w", err)
	}

	q.chMu.Lock()
	defer q.chMu.Unlock()

	if err := q.ensureChannel(); err != nil {
		return err
	}

	err = q.publishConfirmedLocked(ctx, priorityQueues[PriorityUrgent], amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		Body:         data,
	})
	if err != nil {
		q.unhealthy = true
	}
	return err
}

func (q *TaskQueue) publishConfirmedLocked(ctx context.Context, queueName string, msg amqp.Publishing) error {
	confirmation, err := q.ch.PublishWithDeferredConfirmWithContext(ctx, "", queueName, false, false, msg)
	if err != nil {
		return err
	}
	if confirmation == nil {
		return errors.New("RabbitMQ publisher confirm is not enabled")
	}
	acked, err := confirmation.WaitContext(ctx)
	if err != nil {
		return fmt.Errorf("RabbitMQ publisher confirm wait failed: %w", err)
	}
	if !acked {
		return errors.New("RabbitMQ rejected published task")
	}
	return nil
}

// ============================================================================
// Pop 出队 — 多优先级降序消费
// ============================================================================

// TryPopTask 完全非阻塞：按优先级从高到低依次 basic.get，立即返回
func (q *TaskQueue) TryPopTask(ctx context.Context, agentID string) (*pb.Task, string, error) {
	if q.mode == "memory" {
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

	if err := q.ensureChannel(); err != nil {
		return nil, "", err
	}

	for _, queueName := range priorityQueues {
		msg, ok, err := q.ch.Get(queueName, false) // autoAck=false, 手动确认
		if err != nil {
			q.unhealthy = true
			return nil, "", fmt.Errorf("RabbitMQ Get error on %s: %w", queueName, err)
		}
		if !ok {
			continue // 此队列为空，尝试下一级
		}

		var task pb.Task
		if err := json.Unmarshal(msg.Body, &task); err != nil {
			// 格式错误，直接 ACK 掉避免反复消费
			if ackErr := q.ch.Ack(msg.DeliveryTag, false); ackErr != nil {
				q.unhealthy = true
			}
			log.Printf("[TaskQueue] Discarded malformed message from %s: %v", queueName, err)
			continue
		}

		// 生成 compositeID 并记录投递信息
		compositeID := q.deliveryID(queueName, msg.DeliveryTag)
		q.pendingAcks.Store(compositeID, &pendingDelivery{
			tag:        msg.DeliveryTag,
			queueName:  queueName,
			agentID:    agentID,
			claimedAt:  time.Now(),
			generation: q.generation,
		})

		return &task, compositeID, nil
	}

	return nil, "", nil // 全部为空
}

// PopTask 阻塞版本：先尝试立即获取，失败后等待 500ms 重试一次
func (q *TaskQueue) PopTask(ctx context.Context, agentID string) (*pb.Task, string, error) {
	if q.mode == "memory" {
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
	if q.mode == "memory" || compositeID == "" {
		return nil
	}

	q.chMu.Lock()
	defer q.chMu.Unlock()
	val, ok := q.pendingAcks.Load(compositeID)
	if !ok {
		return nil // 已确认、已失效或未知
	}
	pd := val.(*pendingDelivery)
	if pd.generation != q.generation {
		q.pendingAcks.Delete(compositeID)
		return nil
	}

	if err := q.ensureChannel(); err != nil {
		return err
	}
	if pd.generation != q.generation {
		q.pendingAcks.Delete(compositeID)
		return nil
	}
	if err := q.ch.Ack(pd.tag, false); err != nil {
		q.unhealthy = true
		return err
	}
	q.pendingAcks.Delete(compositeID)
	return nil
}

// NackTask 拒绝并重新入队（用于标签不匹配退回）
func (q *TaskQueue) NackTask(ctx context.Context, compositeID string) error {
	if q.mode == "memory" || compositeID == "" {
		return nil
	}

	q.chMu.Lock()
	defer q.chMu.Unlock()
	val, ok := q.pendingAcks.Load(compositeID)
	if !ok {
		return nil
	}
	pd := val.(*pendingDelivery)
	if pd.generation != q.generation {
		q.pendingAcks.Delete(compositeID)
		return nil
	}

	if err := q.ensureChannel(); err != nil {
		return err
	}
	if pd.generation != q.generation {
		q.pendingAcks.Delete(compositeID)
		return nil
	}
	if err := q.ch.Nack(pd.tag, false, true); err != nil { // requeue=true
		q.unhealthy = true
		return err
	}
	q.pendingAcks.Delete(compositeID)
	return nil
}

// ============================================================================
// 队列监控
// ============================================================================

// QueueDepth 返回各优先级队列中可消费的消息数（Ready 状态）
func (q *TaskQueue) QueueDepth(ctx context.Context) map[string]int64 {
	depths := make(map[string]int64)
	if q.mode == "memory" {
		q.mem.mu.Lock()
		depths["memory"] = int64(len(q.mem.tasks))
		q.mem.mu.Unlock()
		return depths
	}

	q.chMu.Lock()
	defer q.chMu.Unlock()
	if err := q.ensureChannel(); err != nil {
		log.Printf("[TaskQueue] QueueDepth unavailable: %v", err)
		return depths
	}

	pendingByQueue := q.pendingCountByQueue()

	for _, queueName := range priorityQueues {
		info, err := q.ch.QueueInspect(queueName)
		if err != nil {
			q.unhealthy = true
			log.Printf("[TaskQueue] QueueDepth inspect %s failed: %v", queueName, err)
			break
		}
		// QueueInspect.Messages = Ready + Unacked
		// 可消费积压 = 总量 - 当前进程持有的未确认投递
		ready := int64(info.Messages) - pendingByQueue[queueName]
		if ready < 0 {
			ready = 0
		}
		depths[queueName] = ready
	}
	return depths
}

// PendingCount 返回各队列中正在处理中（未 ACK）的消息数
func (q *TaskQueue) PendingCount(ctx context.Context) map[string]int64 {
	return q.pendingCountByQueue()
}

func (q *TaskQueue) pendingCountByQueue() map[string]int64 {
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

	for {
		select {
		case <-q.done:
			return
		case <-ticker.C:
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

func newQueueEpoch() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return hex.EncodeToString(random[:])
	}
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), queueEpochCounter.Add(1))
}

func (q *TaskQueue) deliveryID(queueName string, deliveryTag uint64) string {
	return fmt.Sprintf("%s|%d|%s|%d", q.epoch, q.generation, queueName, deliveryTag)
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

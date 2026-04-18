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
	return queue
}

func (q *TaskQueue) Mode() string {
	if q.mode == "" {
		return "memory"
	}
	return q.mode
}

// PushTask 将一个扫描任务压入队列底部
func (q *TaskQueue) PushTask(ctx context.Context, task *pb.Task) error {
	if q.client == nil {
		q.mem.pushBack(task)
		return nil
	}

	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("task marshal error: %w", err)
	}

	return q.client.LPush(ctx, q.queueKey, data).Err()
}

// PushTaskToFront 将一个恢复的任务推到队列最前方优先执行
func (q *TaskQueue) PushTaskToFront(ctx context.Context, task *pb.Task) error {
	if q.client == nil {
		q.mem.pushFront(task)
		return nil
	}

	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("task marshal error: %w", err)
	}
	return q.client.RPush(ctx, q.queueKey, data).Err()
}

// PopTask 从队列顶部弹出一个等待执行的任务 (非阻塞)
// 返回值为 nil，表示队列为空
func (q *TaskQueue) PopTask(ctx context.Context) (*pb.Task, error) {
	if q.client == nil {
		return q.mem.pop(ctx, time.Second)
	}

	// 等待1秒出队，防止 CPU 轮询过高
	result, err := q.client.BRPop(ctx, 1*time.Second, q.queueKey).Result()
	if err == redis.Nil {
		return nil, nil // 队列为空
	} else if err != nil {
		return nil, fmt.Errorf("BRPop error: %w", err)
	}

	// BRPop 返回格式为 [keyName, value]
	if len(result) != 2 {
		return nil, fmt.Errorf("unexpected brpop format")
	}

	var task pb.Task
	if err := json.Unmarshal([]byte(result[1]), &task); err != nil {
		return nil, fmt.Errorf("task unmarshal error: %w", err)
	}

	return &task, nil
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

package db

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

type RootTask struct {
	ID              string `gorm:"primaryKey"`
	TenantID        string `gorm:"default:'default';index"`
	UserID          string `gorm:"index"`
	Name            string
	OriginalTargets string `gorm:"type:text"`
	Status          string `gorm:"index"`
	TotalChunks     int
	CompletedChunks int
	Config          string `gorm:"type:text"`
	Priority        int
	TimeoutSec      int
	RuleVersion     string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type SubTask struct {
	ID            string `gorm:"primaryKey"`
	TenantID      string `gorm:"default:'default';index"`
	RootTaskID    string `gorm:"index"`
	ChunkTargets  string `gorm:"type:text"`
	Status        string `gorm:"index"`
	AgentID       string `gorm:"index"`
	Config        string `gorm:"type:text"`
	StreamMsgID   string
	Priority      int    `gorm:"default:1;index"` // 0=最高, 1=普通, 2=低
	AgentSelector string `gorm:"type:text"`       // JSON: 节点标签选择器
	TimeoutSec    int
	RetryCount    int
	MaxRetry      int    `gorm:"default:3"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Node struct {
	AgentID      string `gorm:"primaryKey"`
	IP           string
	Status       string
	Token        string
	Tags         string
	Version      string
	Capacity     int    `gorm:"default:1"`
	RunningTasks int    `gorm:"default:0"`
	RuleVersion  string
	LastBeat     int64
	CreatedAt    time.Time
}

// User 用户模型 - 多租户用户管理
type User struct {
	ID           uint   `gorm:"primaryKey;autoIncrement"`
	TenantID     string `gorm:"default:'default';index"`
	Username     string `gorm:"uniqueIndex"`
	PasswordHash string
	Role         string `gorm:"default:'viewer'"` // admin, operator, viewer
	Status       string `gorm:"default:'active'"` // active, disabled
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// SystemConfig 系统配置键值存储
type SystemConfig struct {
	Key       string `gorm:"primaryKey"`
	Value     string `gorm:"type:text"`
	UpdatedAt time.Time
}

type Asset struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TenantID    string `gorm:"default:'default';index"`
	TaskID      string `gorm:"uniqueIndex:idx_asset_dedupe"`
	Target      string `gorm:"uniqueIndex:idx_asset_dedupe"`
	Protocol    string `gorm:"uniqueIndex:idx_asset_dedupe"`
	Port        int
	URL         string `gorm:"type:text"`
	Title       string
	Service     string
	CertSubject string // TLS 证书主体
	CertExpiry  *time.Time // TLS 证书过期时间
	CreatedAt   time.Time
}

type FingerprintHit struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TenantID    string `gorm:"default:'default';index"`
	TaskID      string `gorm:"uniqueIndex:idx_fp_dedupe"`
	Target      string `gorm:"uniqueIndex:idx_fp_dedupe"`
	ProductName string `gorm:"uniqueIndex:idx_fp_dedupe"`
	RuleName    string
	Evidence    string `gorm:"type:text"`
	CreatedAt   time.Time
}

type Vulnerability struct {
	ID        uint   `gorm:"primaryKey;autoIncrement"`
	TenantID  string `gorm:"default:'default';index"`
	TaskID    string `gorm:"uniqueIndex:idx_vuln_new_dedupe"`
	Target    string `gorm:"uniqueIndex:idx_vuln_new_dedupe"`
	Plugin    string `gorm:"uniqueIndex:idx_vuln_new_dedupe"`
	Severity  string
	Payload   string `gorm:"type:text"`
	CreatedAt time.Time
}

// Arsenal represents dynamic rule files synced to agents.
type Arsenal struct {
	ID           string `gorm:"primaryKey"`
	TenantID     string `gorm:"default:'default';index"`
	Type         string `gorm:"index"`
	FileName     string `gorm:"index"`
	Content      string
	Hash         string
	PreviousHash string // 上一版本 Hash（用于回滚）
	Version      int    `gorm:"default:1"` // 自增版本号
	State        string `gorm:"default:'Draft';index"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AgentLog 遥测日志模型
type AgentLog struct {
	ID        uint   `gorm:"primaryKey;autoIncrement"`
	AgentID   string `gorm:"index"`
	Level     string // INFO, WARN, ERROR
	Message   string `gorm:"type:text"`
	Timestamp int64  `gorm:"index"`
	CreatedAt time.Time
}

func InitDB(dsn string) {
	if strings.TrimSpace(dsn) == "" {
		dsn = "host=127.0.0.1 user=postgres password=root dbname=dddd port=5432 sslmode=disable"
		log.Printf("No DSN provided, using default: %s", dsn)
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to initialize PostgreSQL database: %v", err)
	}

	if err := db.AutoMigrate(&RootTask{}, &SubTask{}, &Node{}, &Asset{}, &FingerprintHit{}, &Vulnerability{}, &Arsenal{}, &User{}, &SystemConfig{}, &AgentLog{}); err != nil {
		log.Fatalf("failed to auto-migrate PostgreSQL database: %v", err)
	}

	DB = db
	log.Printf("PostgreSQL database initialized successfully.")
}

func isPostgresDSN(dsn string) bool {
	normalized := strings.ToLower(strings.TrimSpace(dsn))
	return strings.HasPrefix(normalized, "postgres://") ||
		strings.HasPrefix(normalized, "postgresql://") ||
		strings.Contains(normalized, "host=")
}

func UpdateNodeHeartbeat(agentID string) error {
	return DB.Model(&Node{}).Where("agent_id = ?", agentID).
		Update("last_beat", time.Now().UnixMilli()).Error
}

func CompleteTask(taskID string, status string) error {
	return DB.Model(&SubTask{}).Where("id = ?", taskID).
		Update("status", status).Error
}

var assetBuffer = make(chan Asset, 10000)
var fpBuffer = make(chan FingerprintHit, 10000)
var vulnBuffer2 = make(chan Vulnerability, 10000)

var OnResultBatchSaved func(count int, rType string)

func StartBatchWriters() {
	go startGenericBatchWriter(assetBuffer, func(batch []Asset) {
		DB.CreateInBatches(batch, 500)
		if OnResultBatchSaved != nil && len(batch) > 0 {
			OnResultBatchSaved(len(batch), "asset")
		}
	})
	go startGenericBatchWriter(fpBuffer, func(batch []FingerprintHit) {
		DB.CreateInBatches(batch, 500)
		if OnResultBatchSaved != nil && len(batch) > 0 {
			OnResultBatchSaved(len(batch), "fingerprint")
		}
	})
	go startGenericBatchWriter(vulnBuffer2, func(batch []Vulnerability) {
		DB.CreateInBatches(batch, 500)
		if OnResultBatchSaved != nil && len(batch) > 0 {
			OnResultBatchSaved(len(batch), "vuln")
		}
	})
}

func startGenericBatchWriter[T any](ch chan T, saveFunc func(batch []T)) {
	var batch []T
	ticker := time.NewTicker(200 * time.Millisecond)
	for {
		select {
		case v := <-ch:
			batch = append(batch, v)
			if len(batch) >= 500 {
				saveFunc(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				saveFunc(batch)
				batch = batch[:0]
			}
		}
	}
}

func AddResultAsync(taskID string, payloadType string, payloadJSON string) {
	target := "unknown"
	var p map[string]interface{}
	var port int
	var service, title, severity, plugin string

	if err := json.Unmarshal([]byte(payloadJSON), &p); err == nil {
		// 提取 target
		if t, ok := p["target"].(string); ok {
			target = t
		} else if t, ok := p["host"].(string); ok {
			target = t
		} else if t, ok := p["url"].(string); ok {
			target = t
		}
		// 精细化字段提取
		if v, ok := p["port"].(float64); ok {
			port = int(v)
		}
		if v, ok := p["service"].(string); ok {
			service = v
		}
		if v, ok := p["title"].(string); ok {
			title = v
		}
		if v, ok := p["severity"].(string); ok {
			severity = v
		}
		if v, ok := p["plugin"].(string); ok {
			plugin = v
		} else if v, ok := p["name"].(string); ok {
			plugin = v
		}
	}

	switch payloadType {
	case "asset", "port_scan", "subdomain":
		assetBuffer <- Asset{
			TaskID: taskID, Target: target, Protocol: payloadType,
			Port: port, URL: payloadJSON, Title: title, Service: service,
			CreatedAt: time.Now(),
		}
	case "fingerprint", "web_fingerprint", "tech":
		productName := payloadType
		if plugin != "" {
			productName = plugin
		}
		fpBuffer <- FingerprintHit{
			TaskID: taskID, Target: target, ProductName: productName,
			Evidence: payloadJSON, CreatedAt: time.Now(),
		}
	default: // nuclei, gopoc
		if severity == "" {
			severity = "Unknown"
		}
		if plugin == "" {
			plugin = payloadType
		}
		vulnBuffer2 <- Vulnerability{
			TaskID: taskID, Target: target, Plugin: plugin,
			Severity: severity, Payload: payloadJSON, CreatedAt: time.Now(),
		}
	}
}

func SubTaskToProto(task *SubTask) (*pb.Task, error) {
	var targets []string
	if task.ChunkTargets != "" {
		if err := json.Unmarshal([]byte(task.ChunkTargets), &targets); err != nil {
			return nil, err
		}
	}

	config := []byte("{}")
	if task.Config != "" {
		config = []byte(task.Config)
	}

	return &pb.Task{
		TaskId:     task.ID,
		Targets:    targets,
		Config:     config,
		Priority:   int32(task.Priority),
		TimeoutSec: int32(task.TimeoutSec),
	}, nil
}

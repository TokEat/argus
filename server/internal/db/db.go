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
	ID           string `gorm:"primaryKey"`
	TenantID     string `gorm:"default:'default';index"`
	RootTaskID   string `gorm:"index"`
	ChunkTargets string `gorm:"type:text"`
	Status        string `gorm:"index"`
	AgentID       string `gorm:"index"`
	Config        string `gorm:"type:text"`
	StreamMsgID   string
	TimeoutSec    int
	RetryCount   int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Node struct {
	AgentID   string `gorm:"primaryKey"`
	IP        string
	Status    string
	Token     string
	Tags      string
	LastBeat  int64
	CreatedAt time.Time
}

type Asset struct {
	ID        uint   `gorm:"primaryKey;autoIncrement"`
	TenantID  string `gorm:"default:'default';index"`
	TaskID    string `gorm:"uniqueIndex:idx_asset_dedupe"`
	Target    string `gorm:"uniqueIndex:idx_asset_dedupe"`
	Protocol  string `gorm:"uniqueIndex:idx_asset_dedupe"`
	Port      int
	URL       string `gorm:"type:text"`
	Title     string
	Service   string
	CreatedAt time.Time
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
	ID        string `gorm:"primaryKey"`
	TenantID  string `gorm:"default:'default';index"`
	Type      string `gorm:"index"`
	FileName  string `gorm:"index"`
	Content   string
	Hash      string
	State     string `gorm:"default:'Draft';index"`
	CreatedAt time.Time
	UpdatedAt time.Time
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

	if err := db.AutoMigrate(&RootTask{}, &SubTask{}, &Node{}, &Asset{}, &FingerprintHit{}, &Vulnerability{}, &Arsenal{}); err != nil {
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
	if err := json.Unmarshal([]byte(payloadJSON), &p); err == nil {
		if t, ok := p["target"].(string); ok {
			target = t
		} else if t, ok := p["host"].(string); ok {
			target = t
		} else if t, ok := p["url"].(string); ok {
			target = t
		}
	}

	switch payloadType {
	case "asset", "port_scan", "subdomain":
		assetBuffer <- Asset{TaskID: taskID, Target: target, Protocol: payloadType, URL: payloadJSON, CreatedAt: time.Now()}
	case "fingerprint", "web_fingerprint", "tech":
		fpBuffer <- FingerprintHit{TaskID: taskID, Target: target, ProductName: payloadType, Evidence: payloadJSON, CreatedAt: time.Now()}
	default: // nuclei, gopoc
		vulnBuffer2 <- Vulnerability{TaskID: taskID, Target: target, Plugin: payloadType, Severity: "Unknown", Payload: payloadJSON, CreatedAt: time.Now()}
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
		TaskId:  task.ID,
		Targets: targets,
		Config:  config,
	}, nil
}

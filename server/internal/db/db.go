package db

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

type Task struct {
	ID        string `gorm:"primaryKey"`
	Name      string
	Status    string `gorm:"index"`
	AgentID   string `gorm:"index"`
	Targets   string
	Config    string
	CreatedAt time.Time
	UpdatedAt time.Time
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

type Vuln struct {
	ID        uint `gorm:"primaryKey;autoIncrement"`
	TaskID    string
	Target    string
	Plugin    string
	Severity  string
	Payload   string
	CreatedAt time.Time
}

// Arsenal represents dynamic rule files synced to agents.
type Arsenal struct {
	ID        string `gorm:"primaryKey"`
	Type      string `gorm:"index"`
	FileName  string `gorm:"index"`
	Content   string
	Hash      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func InitDB(dsn string) {
	if strings.TrimSpace(dsn) == "" {
		dsn = "data/dddd.db"
	}

	db, driverName, err := openDB(dsn)
	if err != nil {
		log.Fatalf("failed to initialize %s database: %v", driverName, err)
	}

	if err := db.AutoMigrate(&Task{}, &Node{}, &Vuln{}, &Arsenal{}); err != nil {
		log.Fatalf("failed to auto-migrate %s database: %v", driverName, err)
	}

	DB = db
	log.Printf("%s database initialized successfully.", driverName)
}

func openDB(dsn string) (*gorm.DB, string, error) {
	if isPostgresDSN(dsn) {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		return db, "PostgreSQL", err
	}

	dir := filepath.Dir(dsn)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, "SQLite", err
		}
	}

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	return db, "SQLite", err
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
	return DB.Model(&Task{}).Where("id = ?", taskID).
		Update("status", status).Error
}

func AddVuln(taskID string, payloadType string, payloadJSON string) error {
	v := Vuln{
		TaskID:    taskID,
		Plugin:    payloadType,
		Severity:  "Unknown",
		Payload:   payloadJSON,
		CreatedAt: time.Now(),
	}
	return DB.Create(&v).Error
}

func TaskToProto(task *Task) (*pb.Task, error) {
	var targets []string
	if task.Targets != "" {
		if err := json.Unmarshal([]byte(task.Targets), &targets); err != nil {
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

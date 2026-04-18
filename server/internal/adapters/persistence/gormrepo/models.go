package gormrepo

import "time"

type RootTaskModel struct {
	ID              string `gorm:"primaryKey"`
	TenantID        string `gorm:"index"`
	Name            string
	Status          string `gorm:"index"`
	OriginalTargets string `gorm:"type:text"`
	ConfigJSON      string `gorm:"type:text"`
	RuleVersion     string `gorm:"index"`
	Priority        int
	TimeoutSeconds  int
	TotalChunks     int
	CompletedChunks int
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type SubTaskModel struct {
	ID             string `gorm:"primaryKey"`
	RootTaskID     string `gorm:"index"`
	Status         string `gorm:"index"`
	ChunkTargets   string `gorm:"type:text"`
	ConfigJSON     string `gorm:"type:text"`
	RuleVersion    string `gorm:"index"`
	AssignedAgent  string `gorm:"index"`
	RetryCount     int
	MaxRetryCount  int
	TimeoutSeconds int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type NodeModel struct {
	AgentID       string `gorm:"primaryKey"`
	Version       string
	Status        string `gorm:"index"`
	TagsJSON      string `gorm:"type:text"`
	Capacity      int
	RunningTasks  int
	RuleVersion   string
	LastHeartbeat time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type RuleBundleModel struct {
	Version   string `gorm:"primaryKey"`
	Status    string `gorm:"index"`
	Hash      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type RuleArtifactModel struct {
	ID        string `gorm:"primaryKey"`
	Bundle    string `gorm:"index"`
	Type      string `gorm:"index"`
	FileName  string `gorm:"index"`
	Hash      string
	Content   string `gorm:"type:text"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type AssetModel struct {
	ID          string `gorm:"primaryKey"`
	TaskID      string `gorm:"index"`
	Target      string `gorm:"index"`
	IP          string
	Port        int
	Protocol    string
	URL         string
	Title       string
	Certificate string `gorm:"type:text"`
	CreatedAt   time.Time
}

type FingerprintHitModel struct {
	ID        string `gorm:"primaryKey"`
	TaskID    string `gorm:"index"`
	Target    string `gorm:"index"`
	Product   string `gorm:"index"`
	Version   string
	MatchRule string `gorm:"type:text"`
	MatchPath string
	CreatedAt time.Time
}

type VulnerabilityModel struct {
	ID         string `gorm:"primaryKey"`
	TaskID     string `gorm:"index"`
	Target     string `gorm:"index"`
	Name       string `gorm:"index"`
	Severity   string `gorm:"index"`
	SourceType string
	Evidence   string `gorm:"type:text"`
	CreatedAt  time.Time
}

// Package arsenal 弹药库管理模块。
// 提供指纹、POC、Workflow、主动探测路径的 CRUD 和导入导出能力。
// Server REST API 与扫描运行时共用此包的数据模型与业务逻辑。
package arsenal

import "time"

// Fingerprint 指纹规则。
// 每条记录代表一条独立的匹配规则（同一产品可有多条）。
type Fingerprint struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	ProductName string    `gorm:"index;not null" json:"product_name"`
	RuleExpr    string    `gorm:"not null" json:"rule_expr"`           // 布尔表达式，如 body="nacos" && title="Nacos"
	Category    string    `gorm:"index;default:'web'" json:"category"` // web / service / iot
	Tags        string    `json:"tags"`                                // JSON 数组，如 ["java","中间件"]
	Enabled     bool      `gorm:"default:true" json:"enabled"`
	Source      string    `gorm:"default:'builtin'" json:"source"` // builtin / user / community
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Poc 漏洞检测模板。
type Poc struct {
	ID             uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Name           string    `gorm:"uniqueIndex;not null" json:"name"`     // 模板 ID，如 CVE-2023-12345
	FileName       string    `gorm:"index;not null" json:"file_name"`      // 完整文件名
	Content        string    `json:"-"`                                    // Nuclei YAML 全文（列表查询时不返回）
	ContentHash    string    `json:"content_hash"`                         // MD5
	Severity       string    `gorm:"index;default:'info'" json:"severity"` // info/low/medium/high/critical
	ExecutionClass string    `gorm:"index;default:'detection'" json:"execution_class"`
	RiskLevel      string    `gorm:"index;default:'unknown'" json:"risk_level"`
	Tags           string    `json:"tags"` // JSON 数组
	Author         string    `json:"author"`
	Description    string    `json:"description"`
	Enabled        bool      `gorm:"default:true" json:"enabled"`
	Source         string    `gorm:"default:'builtin'" json:"source"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ActiveFingerprint is one independently versioned Nuclei behavior probe.
type ActiveFingerprint struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Name         string    `gorm:"index;not null" json:"name"`
	FileName     string    `gorm:"uniqueIndex;not null" json:"file_name"`
	ProductName  string    `gorm:"index;not null" json:"product_name"`
	Content      string    `json:"-"`
	ContentHash  string    `json:"content_hash"`
	AutoEligible bool      `gorm:"index" json:"auto_eligible"`
	Enabled      bool      `gorm:"default:true" json:"enabled"`
	Source       string    `gorm:"default:'server'" json:"source"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// PocAsset stores non-YAML files required by Nuclei templates, such as helpers payloads and wordlists.
type PocAsset struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	RelativePath string    `gorm:"uniqueIndex;not null" json:"relative_path"`
	Content      string    `json:"-"`
	ContentHash  string    `json:"content_hash"`
	Enabled      bool      `gorm:"default:true" json:"enabled"`
	Source       string    `gorm:"default:'server'" json:"source"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ConfigAsset stores runtime config files that affect scan behavior but are not rule YAML files.
type ConfigAsset struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	RelativePath string    `gorm:"uniqueIndex;not null" json:"relative_path"`
	Content      string    `json:"-"`
	ContentHash  string    `json:"content_hash"`
	Enabled      bool      `gorm:"default:true" json:"enabled"`
	Source       string    `gorm:"default:'server'" json:"source"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Workflow 指纹→POC 映射关系。
type Workflow struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	ProductName string    `gorm:"index;not null" json:"product_name"` // 对应 Fingerprint.ProductName
	PocName     string    `gorm:"index;not null" json:"poc_name"`     // 对应 Poc.Name 或文件名
	MatchType   string    `gorm:"not null" json:"match_type"`         // root / dir / base / dir-fallback
	Enabled     bool      `gorm:"default:true" json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DirProbe 主动指纹探测路径。
type DirProbe struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Path        string    `gorm:"index;not null" json:"path"`         // 探测路径，如 /nacos/
	ProductName string    `gorm:"index;not null" json:"product_name"` // 关联产品名
	Enabled     bool      `gorm:"default:true" json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

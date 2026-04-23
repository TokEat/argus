package db

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var DB *gorm.DB

// WSBroadcastHook is called to push real-time updates to connected WebSocket clients
var WSBroadcastHook func(msg interface{})

type Project struct {
	ID            string `gorm:"primaryKey"`
	TenantID      string `gorm:"default:'default';index"`
	Name          string `gorm:"index"`
	Description   string `gorm:"type:text"`
	Tags          string `gorm:"type:jsonb"`
	SeedTargets   string `gorm:"type:jsonb"`
	Scope         string `gorm:"type:jsonb"`
	DefaultConfig string `gorm:"type:jsonb"`
	NodeAffinity  string `gorm:"type:jsonb"`
	Status        string `gorm:"default:'active';index"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     gorm.DeletedAt `gorm:"index"`
}

type ProjectMember struct {
	ProjectID string `gorm:"primaryKey"`
	UserID    string `gorm:"primaryKey"`
	Role      string `gorm:"default:'operator'"`
	CreatedAt time.Time
}

type CronTask struct {
	ID        string `gorm:"primaryKey"`
	ProjectID string `gorm:"index"`
	Name      string
	CronExpr  string     `gorm:"index"`
	Targets   string     `gorm:"type:jsonb"`
	Config    string     `gorm:"type:jsonb"`
	NextRunAt *time.Time `gorm:"index"`
	Status    string     `gorm:"default:'active';index"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type RootTask struct {
	ID               string `gorm:"primaryKey"`
	TenantID         string `gorm:"default:'default';index"`
	ProjectID        string `gorm:"index"`
	CronTaskID       string `gorm:"index"`
	UserID           string `gorm:"index"`
	Name             string
	OriginalTargets  string `gorm:"type:text"`
	Status           string `gorm:"index"`
	TotalChunks      int    // 批次总数（聚合后的 SubTask 数量）
	CompletedChunks  int    // 已完成批次数
	TotalTargets     int    // 原始目标总数（用于目标维度进度）
	CompletedTargets int    // 已完成目标数
	Config           string `gorm:"type:text"`
	Priority         int
	TimeoutSec       int
	RuleVersion      string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type SubTask struct {
	ID            string `gorm:"primaryKey"`
	TenantID      string `gorm:"default:'default';index"`
	ProjectID     string `gorm:"index"`
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
	MaxRetry      int `gorm:"default:3"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Node struct {
	TenantID       string `gorm:"default:'default';index"`
	AgentID        string `gorm:"primaryKey"`
	IP             string
	Status         string
	Token          string
	Tags           string
	Version        string
	Capacity       int    `gorm:"default:1"`
	RunningTasks   int    `gorm:"default:0"`
	RunningTaskIDs string `gorm:"type:text"` // JSON array of task IDs
	RuleVersion    string
	OS             string
	Arch           string
	CPUUsage       float32
	MemUsage       float32
	LastBeat       int64
	CreatedAt      time.Time
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

type Domain struct {
	ID        uint   `gorm:"primaryKey;autoIncrement"`
	TenantID  string `gorm:"default:'default';index:idx_domain_dedupe"`
	ProjectID string `gorm:"index:idx_domain_dedupe,unique"`
	Name      string `gorm:"index:idx_domain_dedupe,unique"`
	TaskID    string `gorm:"index"`
	Tags      string `gorm:"type:jsonb"`
	Records   string `gorm:"type:jsonb"`
	ICP       string
	Whois     string `gorm:"type:jsonb"`
	Status    string `gorm:"default:'alive';index"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Asset struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TenantID    string `gorm:"default:'default';index"`
	ProjectID   string `gorm:"index:idx_asset_dedupe,unique"`
	TaskID      string `gorm:"index"`
	RootTaskID  string `gorm:"index"`
	Target      string `gorm:"index:idx_asset_dedupe,unique"`
	Protocol    string `gorm:"index:idx_asset_dedupe,unique"`
	Port        int
	URL         string `gorm:"type:text"`
	Title       string
	Service     string
	CertSubject string     // TLS 证书主体
	CertExpiry  *time.Time // TLS 证书过期时间
	Tags        string     `gorm:"type:jsonb"`
	Status      string     `gorm:"default:'alive';index"`
	OwnerID     string     `gorm:"index"`
	CredID      string     `gorm:"index"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Credential struct {
	ID        string `gorm:"primaryKey"`
	ProjectID string `gorm:"index"`
	Name      string
	Type      string `gorm:"index"`
	Content   string `gorm:"type:text"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type FingerprintHit struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	TenantID    string `gorm:"default:'default';index"`
	ProjectID   string `gorm:"index:idx_fp_dedupe,unique"`
	TaskID      string `gorm:"index"`
	RootTaskID  string `gorm:"index"`
	Target      string `gorm:"index:idx_fp_dedupe,unique"`
	ProductName string `gorm:"index:idx_fp_dedupe,unique"`
	RuleName    string
	Evidence    string `gorm:"type:text"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Vulnerability struct {
	ID           uint   `gorm:"primaryKey;autoIncrement"`
	TenantID     string `gorm:"default:'default';index"`
	ProjectID    string `gorm:"index:idx_vuln_new_dedupe,unique"`
	TaskID       string `gorm:"index"`
	RootTaskID   string `gorm:"index"`
	Target       string `gorm:"index:idx_vuln_new_dedupe,unique"`
	Plugin       string `gorm:"index:idx_vuln_new_dedupe,unique"`
	Severity     string
	Status       string `gorm:"default:'open';index"`
	Assignee     string `gorm:"index"`
	IgnoreReason string `gorm:"type:text"`
	VerifyTaskID string `gorm:"index"`
	Payload      string `gorm:"type:text"`
	Request      string `gorm:"type:text"` // HTTP 请求包原文
	Response     string `gorm:"type:text"` // HTTP 响应包原文
	Description  string `gorm:"type:text"` // 漏洞描述
	Reference    string `gorm:"type:text"` // 参考链接 (JSON array)
	MatchedAt    string `gorm:"type:text"` // 匹配位置 URL
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type NotificationRule struct {
	ID        uint   `gorm:"primaryKey;autoIncrement"`
	ProjectID string `gorm:"index"`
	Event     string `gorm:"index"`
	Channel   string
	Config    string `gorm:"type:jsonb"`
	Status    string `gorm:"default:'enabled'"`
	CreatedAt time.Time
}

type AssetChangeLog struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	ProjectID  string `gorm:"index"`
	TaskID     string `gorm:"index"`
	EntityType string `gorm:"index"`
	EntityID   uint   `gorm:"index"`
	ChangeType string `gorm:"index"`
	Details    string `gorm:"type:jsonb"`
	CreatedAt  time.Time
}

type Report struct {
	ID        string `gorm:"primaryKey"`
	ProjectID string `gorm:"index"`
	Name      string
	Type      string `gorm:"index"`
	Format    string
	FileURL   string `gorm:"type:text"`
	Status    string `gorm:"default:'pending'"`
	CreatedBy string `gorm:"index"`
	CreatedAt time.Time
}

// Arsenal represents dynamic rule files synced to agents.
type Arsenal struct {
	ID              string `gorm:"primaryKey"`
	TenantID        string `gorm:"default:'default';index"`
	Type            string `gorm:"index"`
	FileName        string `gorm:"index"`
	Content         string
	Hash            string
	PreviousHash    string // 上一版本 Hash（用于回滚）
	PreviousContent string `gorm:"type:text"` // 上一版本内容（用于回滚）
	Version         int    `gorm:"default:1"` // 自增版本号
	State           string `gorm:"default:'Draft';index"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
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
		DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "project_id"}, {Name: "target"}, {Name: "protocol"}},
			DoUpdates: clause.AssignmentColumns([]string{"task_id", "root_task_id", "port", "url", "title", "service", "cert_subject", "cert_expiry", "status", "updated_at"}),
		}).CreateInBatches(batch, 500)
		if OnResultBatchSaved != nil && len(batch) > 0 {
			OnResultBatchSaved(len(batch), "asset")
		}
	})
	go startGenericBatchWriter(fpBuffer, func(batch []FingerprintHit) {
		DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "project_id"}, {Name: "target"}, {Name: "product_name"}},
			DoUpdates: clause.AssignmentColumns([]string{"task_id", "root_task_id", "rule_name", "evidence", "updated_at"}),
		}).CreateInBatches(batch, 500)
		if OnResultBatchSaved != nil && len(batch) > 0 {
			OnResultBatchSaved(len(batch), "fingerprint")
		}
	})
	go startGenericBatchWriter(vulnBuffer2, func(batch []Vulnerability) {
		DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "project_id"}, {Name: "target"}, {Name: "plugin"}},
			DoUpdates: clause.AssignmentColumns([]string{"task_id", "root_task_id", "severity", "payload", "request", "response", "description", "reference", "matched_at", "updated_at", "status"}),
		}).CreateInBatches(batch, 500)
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

// taskOwnerEntry 缓存任务归属信息
type taskOwnerEntry struct {
	ProjectID  string
	TenantID   string
	RootTaskID string
}

// taskOwnerLRU 有界 LRU 缓存，防止长期运行内存膨胀
type taskOwnerLRU struct {
	mu      sync.Mutex
	items   map[string]*taskOwnerEntry
	order   []string // 插入顺序，用于淘汰
	maxSize int
}

func newTaskOwnerLRU(maxSize int) *taskOwnerLRU {
	return &taskOwnerLRU{
		items:   make(map[string]*taskOwnerEntry, maxSize),
		order:   make([]string, 0, maxSize),
		maxSize: maxSize,
	}
}

func (c *taskOwnerLRU) Load(key string) (*taskOwnerEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.items[key]
	return entry, ok
}

func (c *taskOwnerLRU) Store(key string, entry *taskOwnerEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[key]; exists {
		c.items[key] = entry
		return
	}
	// 淘汰最旧的条目
	if len(c.order) >= c.maxSize {
		evictKey := c.order[0]
		c.order = c.order[1:]
		delete(c.items, evictKey)
	}
	c.items[key] = entry
	c.order = append(c.order, key)
}

// taskOwnerCache 有界 LRU：最多缓存 10000 个 taskID 映射
var taskOwnerCache = newTaskOwnerLRU(10000)

// normalizeTarget 将各种格式的 target 归一化为统一格式，
// 确保同一主机在 assets / fingerprint_hits / vulnerabilities 三表中的 target 值一致。
//
// 规则：
//   - 纯 IP → 保持原样: "192.168.1.1"
//   - IP:Port → 保持原样: "192.168.1.1:80"
//   - URL → 提取为 scheme://host:port（保留 scheme 和端口）: "https://example.com:443"
//   - 域名 → 保持原样: "example.com"
func normalizeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "unknown" {
		return raw
	}

	// 尝试解析为 URL
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			host := u.Hostname()
			port := u.Port()
			// 补全默认端口
			if port == "" {
				switch u.Scheme {
				case "https":
					port = "443"
				case "http":
					port = "80"
				}
			}
			if port != "" {
				return u.Scheme + "://" + host + ":" + port
			}
			return u.Scheme + "://" + host
		}
	}

	return raw
}

func splitFingerprintToken(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if !strings.Contains(raw, ",") {
		return []string{raw}
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		result = append(result, part)
	}
	return result
}

func extractFingerprintProductNames(payloadType, plugin string, payload map[string]interface{}) []string {
	candidates := make([]string, 0, 4)

	if plugin != "" {
		candidates = append(candidates, splitFingerprintToken(plugin)...)
	}

	if payload != nil {
		if raw, ok := payload["finger"]; ok {
			switch typed := raw.(type) {
			case []interface{}:
				for _, item := range typed {
					if name, ok := item.(string); ok {
						candidates = append(candidates, splitFingerprintToken(name)...)
					}
				}
			case []string:
				for _, item := range typed {
					candidates = append(candidates, splitFingerprintToken(item)...)
				}
			case string:
				candidates = append(candidates, splitFingerprintToken(typed)...)
			}
		}
	}

	if len(candidates) == 0 {
		fallback := strings.TrimSpace(payloadType)
		switch fallback {
		case "", "Finger", "Active-Finger", "fingerprint", "web_fingerprint", "tech":
		default:
			candidates = append(candidates, fallback)
		}
	}

	seen := make(map[string]struct{}, len(candidates))
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || strings.EqualFold(candidate, "unknown") {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

func AddResultAsync(taskID string, payloadType string, payloadJSON string) {
	// 优先从 LRU 缓存查找任务归属
	projectID := "default_project"
	tenantID := "default"
	rootTaskID := ""
	if entry, ok := taskOwnerCache.Load(taskID); ok {
		projectID = entry.ProjectID
		tenantID = entry.TenantID
		rootTaskID = entry.RootTaskID
	} else {
		// 缓存未命中，查库并缓存结果
		var subTask SubTask
		if err := DB.Select("project_id", "tenant_id", "root_task_id").Where("id = ?", taskID).First(&subTask).Error; err == nil {
			if subTask.ProjectID != "" {
				projectID = subTask.ProjectID
			}
			if subTask.TenantID != "" {
				tenantID = subTask.TenantID
			}
			rootTaskID = subTask.RootTaskID
		}
		taskOwnerCache.Store(taskID, &taskOwnerEntry{ProjectID: projectID, TenantID: tenantID, RootTaskID: rootTaskID})
	}

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

	if WSBroadcastHook != nil {
		WSBroadcastHook(map[string]interface{}{
			"type":    payloadType,
			"target":  target,
			"payload": payloadJSON,
		})
	}

	switch payloadType {
	case "asset", "port_scan", "subdomain",
		"Web", "Protocol", "PortScan", "IPAlive", "Domain", "Domain-Bind":
		// Agent 通过 ddout.OutputMessage 发送的 Type 为大写开头（如 Web/Protocol/PortScan/IPAlive/Domain）
		// 统一归入资产表

		// 对 Web 类型提取更丰富的字段
		if payloadType == "Web" || payloadType == "Domain-Bind" {
			if uri, ok := p["uri"].(string); ok && target == "unknown" {
				target = uri
			}
			if web, ok := p["web"].(map[string]interface{}); ok {
				if t, ok := web["title"].(string); ok && t != "" {
					title = t
				}
				if s, ok := web["status"].(string); ok && s != "" {
					service = "http/" + s
				}
			}
		}
		if payloadType == "PortScan" {
			if ip, ok := p["ip"].(string); ok {
				target = ip
				if portStr, ok := p["port"].(string); ok {
					target = ip + ":" + portStr
				}
			}
		}
		if payloadType == "Protocol" {
			if ip, ok := p["ip"].(string); ok {
				target = ip
				if portStr, ok := p["port"].(string); ok {
					target = ip + ":" + portStr
				}
			}
			if proto, ok := p["protocol"].(string); ok {
				service = proto
			}
		}
		if payloadType == "Domain" {
			if domain, ok := p["domain"].(string); ok {
				target = domain
			}
		}
		if payloadType == "IPAlive" {
			if ip, ok := p["ip"].(string); ok {
				target = ip
			}
		}

		// 归一化 target，确保三表关联一致性
		target = normalizeTarget(target)

		assetBuffer <- Asset{
			TenantID: tenantID, ProjectID: projectID, TaskID: taskID, RootTaskID: rootTaskID, Target: target, Protocol: payloadType,
			Port: port, URL: payloadJSON, Title: title, Service: service,
			Tags: "[]", Status: "alive", CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
	case "fingerprint", "web_fingerprint", "tech",
		"Finger", "Active-Finger":
		// Agent 通过 ddout 发送的指纹 Type 为 Finger/Active-Finger。
		// 原实现将 finger[] 拼接成一个字符串，容易产生“顺序变化导致重复”
		// 和“单产品维度漏报”。这里改为逐产品名写入。
		if uri, ok := p["uri"].(string); ok && target == "unknown" {
			target = uri
		}
		// 归一化 target，确保三表关联一致性
		target = normalizeTarget(target)
		productNames := extractFingerprintProductNames(payloadType, plugin, p)
		if len(productNames) == 0 {
			break
		}
		for _, productName := range productNames {
			fpBuffer <- FingerprintHit{
				TenantID: tenantID, ProjectID: projectID, TaskID: taskID, RootTaskID: rootTaskID, Target: target, ProductName: productName,
				Evidence: payloadJSON, CreatedAt: time.Now(), UpdatedAt: time.Now(),
			}
		}
	case "phase":
		// Agent PhaseHook 发送的阶段进度事件，仅广播到 WebSocket，不入库
		if WSBroadcastHook != nil {
			WSBroadcastHook(map[string]interface{}{
				"type":    "phase",
				"task_id": taskID,
				"payload": payloadJSON,
			})
		}
		return
	default: // nuclei, gopoc, GoPoc, Nuclei
		if severity == "" {
			severity = "Unknown"
		}
		if plugin == "" {
			plugin = payloadType
		}

		var reqData, respData, description, reference, matchedAt string

		// GoPoc 类型提取
		if payloadType == "GoPoc" {
			if goPoc, ok := p["go_poc"].(map[string]interface{}); ok {
				if name, ok := goPoc["poc_name"].(string); ok && name != "" {
					plugin = name
				}
				if t, ok := goPoc["target"].(string); ok && t != "" {
					target = t
				}
				if sec, ok := goPoc["security"].(string); ok && sec != "" {
					severity = sec
				}
				if left, ok := goPoc["InfoLeft"].(string); ok {
					reqData = left
				}
				if right, ok := goPoc["InfoRight"].(string); ok {
					respData = right
				}
				if desc, ok := goPoc["Description"].(string); ok {
					description = desc
				}
			}
		}

		// Nuclei 类型提取：nuclei 字段是完整 ResultEvent 的 JSON 字符串
		if payloadType == "Nuclei" {
			if nucleiStr, ok := p["nuclei"].(string); ok && nucleiStr != "" {
				plugin = nucleiStr // 向后兼容：保留原始字符串作为 plugin

				// 二次解析 ResultEvent JSON，提取 request/response/info 等字段
				var event map[string]interface{}
				if json.Unmarshal([]byte(nucleiStr), &event) == nil {
					// 提取 template-id 作为更精确的 plugin 名
					if tid, ok := event["template-id"].(string); ok && tid != "" {
						plugin = tid
					}
					// 提取 request / response
					if r, ok := event["request"].(string); ok {
						reqData = r
					}
					if r, ok := event["response"].(string); ok {
						respData = r
					}
					// 多步骤 Packet 数组（优先级高于单 request/response）
					if packets, ok := event["interaction"].([]interface{}); ok && len(packets) > 0 {
						// interaction 暂不处理
						_ = packets
					}
					// 提取 matched URL
					if m, ok := event["matched-at"].(string); ok {
						matchedAt = m
					} else if m, ok := event["matched"].(string); ok {
						matchedAt = m
					}
					// 提取 host 作为 target
					if h, ok := event["host"].(string); ok && h != "" {
						target = h
					}
					// 提取 severity
					if info, ok := event["info"].(map[string]interface{}); ok {
						if s, ok := info["severity"].(string); ok && s != "" {
							severity = s
						}
						if d, ok := info["description"].(string); ok {
							description = d
						}
						if refs, ok := info["reference"]; ok {
							if refBytes, err := json.Marshal(refs); err == nil {
								reference = string(refBytes)
							}
						}
						if name, ok := info["name"].(string); ok && name != "" {
							description = name + "\n" + description
						}
					}
				}
			}
		}

		// 归一化 target，确保三表关联一致性
		target = normalizeTarget(target)

		vulnBuffer2 <- Vulnerability{
			TenantID: tenantID, ProjectID: projectID, TaskID: taskID, RootTaskID: rootTaskID, Target: target, Plugin: plugin,
			Severity: severity, Payload: payloadJSON, Status: "open",
			Request: reqData, Response: respData, Description: description,
			Reference: reference, MatchedAt: matchedAt,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
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

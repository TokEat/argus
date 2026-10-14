package db

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"gorm.io/gorm/clause"
)

// CrawlSiteCandidate 主动爬取发现的"同主机不同站点"关联资产候选（资产类别一）。
// 候选站点本身未被抓取，仅由 Agent 从页面链接中提取上报，供服务端 AI/规则
// 判定是否值得收录为资产。AI 子开关开启时进入 AI 研判，关闭时直接确认。
type CrawlSiteCandidate struct {
	ID           uint    `gorm:"primaryKey;autoIncrement"`
	TenantID     string  `gorm:"default:'default';index"`
	ProjectID    string  `gorm:"index"`
	TaskID       string  `gorm:"index"`
	RootTaskID   string  `gorm:"index"`
	SourceURL    string  `gorm:"type:text"` // 发现该链接的页面 URL
	URL          string  `gorm:"type:text"`
	Scheme       string
	Host         string `gorm:"index"`
	Port         int
	LinkContext  string  `gorm:"type:text"`
	SiteType     string  `gorm:"index"` // ''=端口/子域；path_app=路径反代应用；hidden_path=隐藏端点
	DedupeHash   string  `gorm:"index:idx_crawlsite_dedupe,unique"` // sha256(project_id|url)
	AIControl    bool    // 是否走服务端 AI 研判
	AIStatus     string  `gorm:"default:'pending';index"` // pending/confirmed/duplicate/rejected
	AIConfidence float64
	AIReason     string `gorm:"type:text"`
	AssetPromoted bool  // 已 upsert 进 assets(source='crawl')
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// SensitiveFinding 页面/JS 中提取的敏感信息（资产类别二，服务于钓鱼暴露面分析）。
type SensitiveFinding struct {
	ID           uint    `gorm:"primaryKey;autoIncrement"`
	TenantID     string  `gorm:"default:'default';index"`
	ProjectID    string  `gorm:"index"`
	TaskID       string  `gorm:"index"`
	RootTaskID   string  `gorm:"index"`
	SourceURL    string  `gorm:"type:text"`
	Host         string  `gorm:"index"`
	Kind         string  `gorm:"index"` // email/phone/idcard/account/keyword/custom
	Value        string  `gorm:"type:text"`
	Snippet      string  `gorm:"type:text"`
	Context      string  `gorm:"type:text"` // AI 结构化提取结果（jsonb 文本）
	DedupeHash   string  `gorm:"index:idx_sensitive_dedupe,unique"` // sha256(project_id|host|kind|value)
	AIControl    bool
	AIStatus     string `gorm:"default:'pending';index"`
	AIConfidence float64
	AIReason     string `gorm:"type:text"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// crawlSiteDedupeHash 计算关联站点候选的去重哈希。
func crawlSiteDedupeHash(projectID, rawURL string) string {
	sum := sha256.Sum256([]byte(projectID + "|" + rawURL))
	return hex.EncodeToString(sum[:])
}

// sensitiveDedupeHash 计算敏感信息候选的去重哈希。
func sensitiveDedupeHash(projectID, host, kind, value string) string {
	sum := sha256.Sum256([]byte(projectID + "|" + host + "|" + kind + "|" + value))
	return hex.EncodeToString(sum[:])
}

var crawlSiteBuffer = make(chan CrawlSiteCandidate, 10000)
var sensitiveBuffer = make(chan SensitiveFinding, 10000)

// startContentFindingsWriters 启动两类内容结果的批量 upsert 写入。
func startContentFindingsWriters() {
	go startGenericBatchWriter(crawlSiteBuffer, func(batch []CrawlSiteCandidate) {
		unique := make(map[string]CrawlSiteCandidate, len(batch))
		var keys []string
		for _, c := range batch {
			if _, exists := unique[c.DedupeHash]; !exists {
				keys = append(keys, c.DedupeHash)
			}
			unique[c.DedupeHash] = c
		}
		finalBatch := make([]CrawlSiteCandidate, 0, len(unique))
		for _, k := range keys {
			finalBatch = append(finalBatch, unique[k])
		}
		DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "dedupe_hash"}},
			DoUpdates: clause.AssignmentColumns([]string{"task_id", "root_task_id", "source_url", "link_context", "site_type", "updated_at"}),
		}).CreateInBatches(finalBatch, 500)
		if OnResultBatchSaved != nil && len(finalBatch) > 0 {
			OnResultBatchSaved(len(finalBatch), "crawl_site")
		}
	})
	go startGenericBatchWriter(sensitiveBuffer, func(batch []SensitiveFinding) {
		unique := make(map[string]SensitiveFinding, len(batch))
		var keys []string
		for _, s := range batch {
			if _, exists := unique[s.DedupeHash]; !exists {
				keys = append(keys, s.DedupeHash)
			}
			unique[s.DedupeHash] = s
		}
		finalBatch := make([]SensitiveFinding, 0, len(unique))
		for _, k := range keys {
			finalBatch = append(finalBatch, unique[k])
		}
		DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "dedupe_hash"}},
			DoUpdates: clause.AssignmentColumns([]string{"task_id", "root_task_id", "source_url", "snippet", "updated_at"}),
		}).CreateInBatches(finalBatch, 500)
		if OnResultBatchSaved != nil && len(finalBatch) > 0 {
			OnResultBatchSaved(len(finalBatch), "sensitive_info")
		}
	})
}

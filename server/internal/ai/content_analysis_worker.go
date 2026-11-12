package ai

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/shared/proto/go/targetutil"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ContentWorkerOptions 配置内容分析（关联资产研判 + 敏感信息提取 + 资产回流）后台 worker。
type ContentWorkerOptions struct {
	Client       ChatClient      // nil → HTTPClient（真实 LLM）
	Interval     time.Duration   // 扫描周期，默认 30s
	InitialDelay time.Duration   // 启动后首次扫描延迟，默认 12s
	DecideBatch  int             // 每 tick 最多研判的关联站点候选数，默认 15
	ExtractBatch int             // 每 tick 一批敏感信息提取条数，默认 8
	PromoteBatch int             // 每 tick 最多回流的资产数，默认 25
}

func (o *ContentWorkerOptions) withDefaults() {
	if o.Interval <= 0 {
		o.Interval = 30 * time.Second
	}
	if o.InitialDelay < 0 {
		o.InitialDelay = 0
	}
	if o.DecideBatch <= 0 {
		o.DecideBatch = 15
	}
	if o.ExtractBatch <= 0 {
		o.ExtractBatch = 8
	}
	if o.PromoteBatch <= 0 {
		o.PromoteBatch = 25
	}
}

// StartContentAnalysisWorker 启动后台 worker：周期研判关联站点候选、批量提取敏感信息，
// 并把 confirmed 的关联站点回流为资产（protocol='crawl'）。不侵入结果上报链路，
// LLM 不可用时静默跳过（行保持 pending 等待下次重试）。
func StartContentAnalysisWorker(ctx context.Context, store *gorm.DB, opts ContentWorkerOptions) {
	opts.withDefaults()
	go func() {
		if opts.InitialDelay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(opts.InitialDelay):
			}
		}
		ticker := time.NewTicker(opts.Interval)
		defer ticker.Stop()
		for {
			RunContentAnalysisTick(ctx, store, opts)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// RunContentAnalysisTick 执行一轮：研判 → 提取 → 资产回流。导出供测试直接驱动单轮。
func RunContentAnalysisTick(ctx context.Context, store *gorm.DB, opts ContentWorkerOptions) {
	opts.withDefaults()
	if !LoadContentAnalysisEnabled(store) {
		return
	}
	cfg, err := LoadConfig(store)
	if err != nil {
		if errors.Is(err, ErrMissingConfig) {
			return // LLM 未配置：保持 pending
		}
		log.Printf("[AI] content analysis load config failed: %v", err)
		return
	}
	client := opts.Client
	if client == nil {
		client = &HTTPClient{}
	}
	decidePendingCrawlSites(ctx, store, client, cfg, opts.DecideBatch)
	extractPendingSensitive(ctx, store, client, cfg, opts.ExtractBatch)
	promoteConfirmedCrawlSites(ctx, store, opts.PromoteBatch)
}

// decidePendingCrawlSites 对 ai_control 且 pending 的关联站点候选做价值/判重研判。
func decidePendingCrawlSites(ctx context.Context, store *gorm.DB, client ChatClient, cfg Config, limit int) {
	var cands []db.CrawlSiteCandidate
	if err := store.WithContext(ctx).
		Where("ai_control = ? AND ai_status = ?", true, "pending").
		Order("id").
		Limit(limit).
		Find(&cands).Error; err != nil {
		log.Printf("[AI] crawl site select failed: %v", err)
		return
	}
	for i := range cands {
		cand := cands[i]
		existing := existingProjectTargets(store, cand.ProjectID)
		raw, err := client.CompleteJSON(ctx, cfg, buildCrawlSiteDecisionMessages(cand, existing))
		if err != nil {
			log.Printf("[AI] crawl site decide failed id=%d: %v", cand.ID, err)
			continue // 保持 pending，下一轮重试
		}
		dec, err := parseCrawlSiteDecision(raw)
		if err != nil {
			log.Printf("[AI] crawl site decide parse failed id=%d: %v", cand.ID, err)
			continue
		}
		if err := store.Model(&db.CrawlSiteCandidate{}).Where("id = ?", cand.ID).Updates(map[string]interface{}{
			"ai_status":     dec.Decision,
			"ai_confidence": dec.Confidence,
			"ai_reason":     dec.Reason,
			"updated_at":    time.Now(),
		}).Error; err != nil {
			log.Printf("[AI] crawl site decide writeback failed id=%d: %v", cand.ID, err)
		}
	}
}

// extractPendingSensitive 对一批 ai_control 且 pending 的敏感信息候选做单次批量提取。
func extractPendingSensitive(ctx context.Context, store *gorm.DB, client ChatClient, cfg Config, limit int) {
	var finds []db.SensitiveFinding
	if err := store.WithContext(ctx).
		Where("ai_control = ? AND ai_status = ?", true, "pending").
		Order("id").
		Limit(limit).
		Find(&finds).Error; err != nil {
		log.Printf("[AI] sensitive select failed: %v", err)
		return
	}
	if len(finds) == 0 {
		return
	}
	raw, err := client.CompleteJSON(ctx, cfg, buildSensitiveExtractionMessages(finds))
	if err != nil {
		log.Printf("[AI] sensitive extraction failed: %v", err)
		return // 整批保持 pending
	}
	verdicts, err := parseSensitiveExtraction(raw)
	if err != nil {
		log.Printf("[AI] sensitive extraction parse failed: %v", err)
		return
	}
	byIndex := make(map[int]SensitiveVerdict, len(verdicts))
	for _, v := range verdicts {
		byIndex[v.Index] = v
	}
	for i := range finds {
		v, ok := byIndex[i]
		if !ok {
			continue // 模型未覆盖该下标：保持 pending
		}
		updates := map[string]interface{}{
			"ai_status":     v.Decision,
			"ai_confidence": v.Confidence,
			"ai_reason":     v.Reason,
			"updated_at":    time.Now(),
		}
		if v.Context != "" {
			updates["context"] = v.Context
		}
		// Kind 重分类：仅 AI 给出的 kind 在 allowlist 内才回写（UI kind 过滤才有意义）。
		// 注：DedupeHash 用原始 kind 计算，此处改 kind 不重算（两行间低概率重复，可接受）。
		if kind := strings.ToLower(strings.TrimSpace(v.Kind)); sensitiveKindAllowlist[kind] {
			updates["kind"] = kind
		}
		if err := store.Model(&db.SensitiveFinding{}).Where("id = ?", finds[i].ID).Updates(updates).Error; err != nil {
			log.Printf("[AI] sensitive writeback failed id=%d: %v", finds[i].ID, err)
		}
	}
}

// promoteConfirmedCrawlSites 把 ai_status=confirmed 且未回流的候选 upsert 进 assets，
// 以 protocol='crawl' 作为独立资产类别，并标记 asset_promoted 防止重复回流。
func promoteConfirmedCrawlSites(ctx context.Context, store *gorm.DB, limit int) {
	var cands []db.CrawlSiteCandidate
	if err := store.WithContext(ctx).
		Where("ai_status = ? AND asset_promoted = ?", "confirmed", false).
		Order("id").
		Limit(limit).
		Find(&cands).Error; err != nil {
		log.Printf("[AI] crawl site promote select failed: %v", err)
		return
	}
	for i := range cands {
		cand := cands[i]
		tagsMap := map[string]interface{}{
			"origin":       "web_crawl",
			"candidate_id": cand.ID,
		}
		// 端口/子域候选维持 host:port；路径反代/隐藏端点候选 target 带首段路径，
		// 使 host:port/app1 与 host:port 成为不同资产（OnConflict 按 target 隔离）。
		target := targetutil.NormalizeTarget(cand.Host + ":" + strconv.Itoa(cand.Port))
		if cand.SiteType == "path_app" || cand.SiteType == "hidden_path" {
			target = targetutil.NormalizeTargetWithPath(cand.URL)
			tagsMap["site_type"] = cand.SiteType
			if u, err := url.Parse(cand.URL); err == nil {
				seg := strings.TrimPrefix(u.Path, "/")
				if j := strings.IndexByte(seg, '/'); j >= 0 {
					seg = seg[:j]
				}
				if seg != "" {
					tagsMap["base_path"] = "/" + strings.ToLower(seg)
				}
			}
		}
		tags, _ := json.Marshal(tagsMap)
		now := time.Now()
		asset := db.Asset{
			TenantID:   cand.TenantID,
			ProjectID:  cand.ProjectID,
			TaskID:     cand.TaskID,
			RootTaskID: cand.RootTaskID,
			Target:     target,
			Protocol:   "crawl",
			Port:       cand.Port,
			URL:        cand.URL,
			Service:    cand.Scheme,
			Tags:       string(tags),
			Status:     "alive",
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		err := store.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "project_id"}, {Name: "target"}, {Name: "protocol"}},
			DoUpdates: clause.AssignmentColumns([]string{"task_id", "root_task_id", "url", "service", "status", "updated_at"}),
		}).Create(&asset).Error
		if err != nil {
			log.Printf("[AI] crawl site promote id=%d failed: %v", cand.ID, err)
			continue // 不标记 asset_promoted，下轮重试
		}
		if err := store.Model(&db.CrawlSiteCandidate{}).Where("id = ?", cand.ID).
			Update("asset_promoted", true).Error; err != nil {
			log.Printf("[AI] crawl site promote mark id=%d failed: %v", cand.ID, err)
		}
	}
}

// existingProjectTargets 返回项目已收录资产的去重 target（截断，供 AI 判重上下文）。
func existingProjectTargets(store *gorm.DB, projectID string) []string {
	var targets []string
	store.Model(&db.Asset{}).
		Where("project_id = ?", projectID).
		Distinct().
		Limit(200).
		Pluck("target", &targets)
	return targets
}

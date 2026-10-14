package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func contentTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.SystemConfig{}, &db.CrawlSiteCandidate{}, &db.SensitiveFinding{}, &db.Asset{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return store
}

func seedCrawlCandidate(t *testing.T, store *gorm.DB, mutate func(*db.CrawlSiteCandidate)) db.CrawlSiteCandidate {
	t.Helper()
	c := db.CrawlSiteCandidate{
		TenantID:   "default",
		ProjectID:  "proj-1",
		TaskID:     "task-1",
		RootTaskID: "root-1",
		SourceURL:  "http://example.com:8080/",
		URL:        "http://admin.example.com:9090/login",
		Scheme:     "http",
		Host:       "admin.example.com",
		Port:       9090,
		DedupeHash: "h-" + time.Now().Format("150405.000000000"),
		AIControl:  true,
		AIStatus:   "pending",
	}
	if mutate != nil {
		mutate(&c)
	}
	if err := store.Create(&c).Error; err != nil {
		t.Fatalf("seed crawl candidate: %v", err)
	}
	return c
}

func seedSensitiveFinding(t *testing.T, store *gorm.DB, value string) db.SensitiveFinding {
	t.Helper()
	f := db.SensitiveFinding{
		TenantID:   "default",
		ProjectID:  "proj-1",
		TaskID:     "task-1",
		RootTaskID: "root-1",
		SourceURL:  "http://example.com/contact",
		Host:       "example.com",
		Kind:       "email",
		Value:      value,
		Snippet:    "contact us at " + value,
		DedupeHash: "s-" + value,
		AIControl:  true,
		AIStatus:   "pending",
	}
	if err := store.Create(&f).Error; err != nil {
		t.Fatalf("seed sensitive finding: %v", err)
	}
	return f
}

func reloadCrawl(t *testing.T, store *gorm.DB, id uint) db.CrawlSiteCandidate {
	t.Helper()
	var c db.CrawlSiteCandidate
	if err := store.First(&c, id).Error; err != nil {
		t.Fatalf("reload crawl: %v", err)
	}
	return c
}

func reloadSensitive(t *testing.T, store *gorm.DB, id uint) db.SensitiveFinding {
	t.Helper()
	var f db.SensitiveFinding
	if err := store.First(&f, id).Error; err != nil {
		t.Fatalf("reload sensitive: %v", err)
	}
	return f
}

func TestContentTickDecidesAndPromotesCrawlSite(t *testing.T) {
	store := contentTestDB(t)
	seedTriageAIConfig(t, store)
	cand := seedCrawlCandidate(t, store, nil)

	client := &fakeErrChatClient{raw: `{"decision":"confirmed","confidence":0.9,"reason":"独立管理后台，值得收录"}`}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: client})

	got := reloadCrawl(t, store, cand.ID)
	if got.AIStatus != CrawlSiteDecisionConfirmed {
		t.Fatalf("expected confirmed, got %s", got.AIStatus)
	}
	if !got.AssetPromoted {
		t.Fatalf("confirmed candidate should be promoted to assets")
	}
	var asset db.Asset
	if err := store.Where("project_id = ? AND protocol = ?", "proj-1", "crawl").First(&asset).Error; err != nil {
		t.Fatalf("expected promoted crawl asset: %v", err)
	}
	if asset.URL != cand.URL || asset.Port != cand.Port {
		t.Fatalf("asset mismatch: url=%s port=%d", asset.URL, asset.Port)
	}
}

func TestContentTickCrawlSiteRejectedNotPromoted(t *testing.T) {
	store := contentTestDB(t)
	seedTriageAIConfig(t, store)
	cand := seedCrawlCandidate(t, store, nil)

	client := &fakeErrChatClient{raw: `{"decision":"rejected","confidence":0.3,"reason":"纯跳转页"}`}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: client})

	got := reloadCrawl(t, store, cand.ID)
	if got.AIStatus != CrawlSiteDecisionRejected {
		t.Fatalf("expected rejected, got %s", got.AIStatus)
	}
	if got.AssetPromoted {
		t.Fatalf("rejected candidate must not be promoted")
	}
	var count int64
	store.Model(&db.Asset{}).Where("protocol = ?", "crawl").Count(&count)
	if count != 0 {
		t.Fatalf("rejected candidate must not create an asset, got %d", count)
	}
}

func TestContentTickExtractsSensitiveBatch(t *testing.T) {
	store := contentTestDB(t)
	seedTriageAIConfig(t, store)
	realOne := seedSensitiveFinding(t, store, "admin@example.com")
	fpOne := seedSensitiveFinding(t, store, "123456")

	raw := `{"verdicts":[` +
		`{"index":0,"decision":"confirmed","value":"admin@example.com","context":"{\"owner\":\"管理员\"}","confidence":0.95,"reason":"真实邮箱"},` +
		`{"index":1,"decision":"rejected","confidence":0.2,"reason":"普通数字误判"}` +
		`]}`
	client := &fakeErrChatClient{raw: raw}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: client})

	if got := reloadSensitive(t, store, realOne.ID); got.AIStatus != SensitiveDecisionConfirmed {
		t.Fatalf("expected confirmed, got %s", got.AIStatus)
	} else if got.Context == "" {
		t.Fatalf("confirmed finding should carry structured context")
	}
	if got := reloadSensitive(t, store, fpOne.ID); got.AIStatus != SensitiveDecisionRejected {
		t.Fatalf("expected rejected, got %s", got.AIStatus)
	}
}

func TestContentTickDisabledSkipsLLM(t *testing.T) {
	store := contentTestDB(t)
	seedTriageAIConfig(t, store)
	if err := store.Save(&db.SystemConfig{Key: ContentAnalysisConfigKeyEnabled, Value: "false", UpdatedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	cand := seedCrawlCandidate(t, store, nil)
	client := &fakeErrChatClient{raw: `{"decision":"confirmed"}`}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: client})
	if client.calls != 0 {
		t.Fatalf("disabled worker must not call LLM, calls=%d", client.calls)
	}
	if got := reloadCrawl(t, store, cand.ID); got.AIStatus != "pending" {
		t.Fatalf("disabled worker must leave rows pending, got %s", got.AIStatus)
	}
}

func TestContentTickMissingConfigStaysPending(t *testing.T) {
	store := contentTestDB(t) // 不配置 LLM
	cand := seedCrawlCandidate(t, store, nil)
	client := &fakeErrChatClient{raw: `{"decision":"confirmed"}`}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: client})
	if got := reloadCrawl(t, store, cand.ID); got.AIStatus != "pending" || got.AssetPromoted {
		t.Fatalf("missing config must stay pending/unpromoted, got %s promoted=%v", got.AIStatus, got.AssetPromoted)
	}
}

func TestContentTickLLMFailureRetriesNextTick(t *testing.T) {
	store := contentTestDB(t)
	seedTriageAIConfig(t, store)
	cand := seedCrawlCandidate(t, store, nil)

	broken := &fakeErrChatClient{raw: "", err: errors.New("llm unreachable")}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: broken})
	if got := reloadCrawl(t, store, cand.ID); got.AIStatus != "pending" {
		t.Fatalf("LLM failure must leave pending, got %s", got.AIStatus)
	}

	healthy := &fakeErrChatClient{raw: `{"decision":"confirmed","confidence":0.8,"reason":"ok"}`}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: healthy})
	got := reloadCrawl(t, store, cand.ID)
	if got.AIStatus != CrawlSiteDecisionConfirmed || !got.AssetPromoted {
		t.Fatalf("healthy tick should decide+promote, got %s promoted=%v", got.AIStatus, got.AssetPromoted)
	}
}

func TestParseCrawlSiteDecisionRejectsGarbage(t *testing.T) {
	if _, err := parseCrawlSiteDecision(`{"decision":"maybe"}`); err == nil {
		t.Fatalf("invalid decision must error")
	}
	if _, err := parseCrawlSiteDecision(`not json`); err == nil {
		t.Fatalf("non-json must error")
	}
	dec, err := parseCrawlSiteDecision("```json\n{\"decision\":\"duplicate\",\"confidence\":1.7,\"reason\":\"重复\"}\n```")
	if err != nil {
		t.Fatalf("fenced json must parse: %v", err)
	}
	if dec.Decision != CrawlSiteDecisionDuplicate || dec.Confidence != 1 {
		t.Fatalf("unexpected parse: %+v", dec)
	}
}

func TestContentTickPromotesPathAppWithPathTarget(t *testing.T) {
	store := contentTestDB(t)
	seedTriageAIConfig(t, store)
	cand := seedCrawlCandidate(t, store, func(c *db.CrawlSiteCandidate) {
		c.SiteType = "path_app"
		c.URL = "http://example.com:8080/app1"
		c.Host = "example.com"
		c.Port = 8080
	})

	client := &fakeErrChatClient{raw: `{"decision":"confirmed","confidence":0.9,"reason":"路径反代的独立应用"}`}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: client})

	var asset db.Asset
	if err := store.Where("project_id = ? AND protocol = ?", "proj-1", "crawl").First(&asset).Error; err != nil {
		t.Fatalf("expected promoted path asset: %v", err)
	}
	if asset.Target != "http://example.com:8080/app1" {
		t.Fatalf("path asset target = %q, want http://example.com:8080/app1", asset.Target)
	}
	if !strings.Contains(asset.Tags, `"site_type":"path_app"`) || !strings.Contains(asset.Tags, `"base_path":"/app1"`) {
		t.Fatalf("path asset tags missing site_type/base_path: %s", asset.Tags)
	}
	if !reloadCrawl(t, store, cand.ID).AssetPromoted {
		t.Fatalf("path candidate should be marked promoted")
	}
}

func TestContentTickPromotesHiddenPathWithPathTarget(t *testing.T) {
	store := contentTestDB(t)
	seedTriageAIConfig(t, store)
	seedCrawlCandidate(t, store, func(c *db.CrawlSiteCandidate) {
		c.SiteType = "hidden_path"
		c.URL = "http://example.com:8080/internal"
		c.Host = "example.com"
		c.Port = 8080
	})

	client := &fakeErrChatClient{raw: `{"decision":"confirmed","confidence":0.8,"reason":"独立内部系统"}`}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: client})

	var asset db.Asset
	if err := store.Where("project_id = ? AND protocol = ?", "proj-1", "crawl").First(&asset).Error; err != nil {
		t.Fatalf("expected promoted hidden_path asset: %v", err)
	}
	if asset.Target != "http://example.com:8080/internal" {
		t.Fatalf("hidden_path asset target = %q, want http://example.com:8080/internal", asset.Target)
	}
}

func TestContentTickPortCandidateKeepsHostPortTarget(t *testing.T) {
	store := contentTestDB(t)
	seedTriageAIConfig(t, store)
	seedCrawlCandidate(t, store, nil) // 默认 SiteType=""，URL=admin.example.com:9090/login

	client := &fakeErrChatClient{raw: `{"decision":"confirmed","confidence":0.9,"reason":"独立后台"}`}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: client})

	var asset db.Asset
	if err := store.Where("project_id = ? AND protocol = ?", "proj-1", "crawl").First(&asset).Error; err != nil {
		t.Fatalf("expected promoted port asset: %v", err)
	}
	// 端口类候选维持 host:port 归一（不带路径），与路径类区分。
	if asset.Target != "admin.example.com:9090" {
		t.Fatalf("port asset target = %q, want admin.example.com:9090", asset.Target)
	}
	if strings.Contains(asset.Tags, "base_path") {
		t.Fatalf("port asset tags must not carry base_path: %s", asset.Tags)
	}
}

func TestContentTickSensitiveKindWriteback(t *testing.T) {
	store := contentTestDB(t)
	seedTriageAIConfig(t, store)
	inAllow := seedSensitiveFinding(t, store, "zhang.wei@example.com")
	outAllow := seedSensitiveFinding(t, store, "li.na@example.com")

	// index0 给 allowlist 内的 username（应回写）；index1 给 allowlist 外的 ssn（应忽略）。
	raw := `{"verdicts":[` +
		`{"index":0,"decision":"confirmed","value":"zhang.wei@example.com","kind":"username","confidence":0.9,"reason":"真实用户名"},` +
		`{"index":1,"decision":"confirmed","value":"li.na@example.com","kind":"ssn","confidence":0.9,"reason":"真实"}` +
		`]}`
	client := &fakeErrChatClient{raw: raw}
	RunContentAnalysisTick(context.Background(), store, ContentWorkerOptions{Client: client})

	if got := reloadSensitive(t, store, inAllow.ID); got.Kind != "username" {
		t.Fatalf("allowlist kind should be written back, got %q", got.Kind)
	}
	if got := reloadSensitive(t, store, outAllow.ID); got.Kind != "email" {
		t.Fatalf("non-allowlist kind must be ignored, got %q", got.Kind)
	}
}

// 提示词契约：mock_llm 依赖"候选列表"/"候选站点 URL"字面量路由，且必须携带
// 新 kind 词表、username_convention 归纳指令与路径前缀指引。
func TestContentAnalysisPromptContent(t *testing.T) {
	sens := buildSensitiveExtractionMessages([]db.SensitiveFinding{{
		Host: "example.com", Kind: "username", Value: "zhang.wei", Snippet: `username: "zhang.wei"`,
	}})
	sensAll := sens[0].Content + sens[1].Content
	for _, want := range []string{"候选列表", "username_convention", "apikey", "token", "secret", "email", "phone", "idcard"} {
		if !strings.Contains(sensAll, want) {
			t.Errorf("sensitive prompt missing %q", want)
		}
	}

	crawl := buildCrawlSiteDecisionMessages(
		db.CrawlSiteCandidate{URL: "http://example.com:8080/app1", Scheme: "http", Host: "example.com", Port: 8080, SiteType: "path_app"},
		nil,
	)
	crawlAll := crawl[0].Content + crawl[1].Content
	for _, want := range []string{"候选站点 URL", "path_app", "hidden_path", "反代", "独立应用"} {
		if !strings.Contains(crawlAll, want) {
			t.Errorf("crawl decision prompt missing %q", want)
		}
	}
}

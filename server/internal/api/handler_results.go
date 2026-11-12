package api

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/server/internal/storage"
	"github.com/TokEat/argus/shared/proto/go/scanplan"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// HostProfile 以主机(IP/域名)为单位聚合的画像
type HostProfile struct {
	Host             string              `json:"host"`
	Ports            []PortInfo          `json:"ports"`
	Assets           []db.Asset          `json:"assets"`
	Fingerprints     []db.FingerprintHit `json:"fingerprints"`
	Vulns            []db.Vulnerability  `json:"vulns"`
	AssetCount       int64               `json:"asset_count"`
	FingerprintCount int64               `json:"fingerprint_count"`
	VulnCount        int64               `json:"vuln_count"`
}

// PortInfo 是某主机上一个端口的聚合视图：跨阶段（PortScan/Nmap/Web 等）按端口号
// 合并成一行。Transport/StatusCode 从 Asset.Service（如 "http/200"）派生。
type PortInfo struct {
	Port       int      `json:"port"`
	Transport  string   `json:"transport"`   // 应用协议/方案: http/https/tcp/...
	Service    string   `json:"service"`     // 合并后的最佳 Service 原值, 如 http/200
	StatusCode int      `json:"status_code"` // HTTP 状态码, 未知=0
	Title      string   `json:"title"`
	URL        string   `json:"url"`
	Stages     []string `json:"stages"`    // 去重保序的阶段标签, 如 ["PortScan","Nmap","Web"]
	AssetIDs   []uint   `json:"asset_ids"` // 该端口贡献的 Asset.ID（前端详情抽屉过滤用）
}

// resolvePortForAsset 从 Asset.Port 或 Target 字符串解析端口号，解析失败返回 0。
func resolvePortForAsset(a db.Asset) int {
	if a.Port != 0 {
		return a.Port
	}
	if a.Target == "" {
		return 0
	}
	if u, err := url.Parse(a.Target); err == nil && u.Port() != "" {
		if pv, e := strconv.Atoi(u.Port()); e == nil {
			return pv
		}
	}
	if _, portStr, err := net.SplitHostPort(a.Target); err == nil {
		if pv, e := strconv.Atoi(portStr); e == nil {
			return pv
		}
	}
	return 0
}

// wellKnownPortTransports 兜底：Service/URL 都拿不到协议时按知名端口推断。
var wellKnownPortTransports = map[int]string{
	80: "http", 81: "http", 8080: "http", 8081: "http", 8000: "http",
	8888: "http", 8008: "http", 8088: "http", 8090: "http",
	443: "https", 8443: "https", 4443: "https",
	53: "dns", 22: "ssh", 21: "ftp", 25: "smtp", 110: "pop3", 143: "imap",
	3306: "mysql", 5432: "postgres", 6379: "redis", 27017: "mongodb",
}

// parseService 从 Asset.Service（如 "http/200"）拆出应用协议与 HTTP 状态码。
// 状态码仅当第二段能解析为 100–599 的整数时采纳。拿不到协议时按
// URL scheme → 知名端口 → "tcp" 兜底。
func parseService(a db.Asset) (transport string, statusCode int) {
	service := strings.TrimSpace(a.Service)
	parts := strings.SplitN(service, "/", 2)
	transport = strings.ToLower(strings.TrimSpace(parts[0]))
	if len(parts) == 2 {
		if code, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && code >= 100 && code <= 599 {
			statusCode = code
		}
	}
	if transport != "" {
		return transport, statusCode
	}
	if a.URL != "" {
		if u, err := url.Parse(a.URL); err == nil && u.Scheme != "" {
			return strings.ToLower(u.Scheme), statusCode
		}
	}
	if tk, ok := wellKnownPortTransports[a.Port]; ok {
		return tk, statusCode
	}
	if port := resolvePortForAsset(a); port != 0 {
		if tk, ok := wellKnownPortTransports[port]; ok {
			return tk, statusCode
		}
	}
	return "tcp", statusCode
}

// serviceRank 给 Service 质量打分：有状态码 > 仅有协议 > 空，用于合并择优。
func serviceRank(service string) int {
	parts := strings.SplitN(strings.TrimSpace(service), "/", 2)
	if len(parts) == 2 {
		if code, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && code >= 100 && code <= 599 {
			return 3
		}
	}
	if strings.TrimSpace(parts[0]) != "" {
		return 2
	}
	return 1
}

// extractHost 从 target 字符串中提取主机部分 (IP 或域名)
// 支持格式: "1.2.3.4:80", "http://example.com:8080", "example.com"
func extractHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return target
	}
	// URL 格式
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			return u.Hostname()
		}
	}
	// IP:Port 或 IP:Port:Extra 格式
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	// 可能是 IP:Port:Proto 三段式
	parts := strings.Split(target, ":")
	if len(parts) >= 2 {
		if ip := net.ParseIP(parts[0]); ip != nil {
			return parts[0]
		}
	}
	return target
}

func getProfiles(c *gin.Context) {
	tenantID := c.GetString("tenant")
	page := 1
	pageSize := 20
	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 200 {
			pageSize = v
		}
	}

	// 步骤 1: 获取所有去重 target 值用于提取 host
	var allTargets []string
	tq := db.DB.Model(&db.Asset{}).Select("DISTINCT target")
	if tenantID != "" {
		tq = tq.Where("tenant_id = ?", tenantID)
	}
	tq, _ = applyProjectScope(c, tq, "project_id")
	if search := c.Query("search"); search != "" {
		tq = tq.Where("target LIKE ?", "%"+search+"%")
	}
	tq.Pluck("target", &allTargets)

	// 步骤 2: 在 Go 层按 host 聚合, 建立 host → targets 映射
	hostTargetsMap := make(map[string][]string)
	for _, t := range allTargets {
		h := extractHost(t)
		hostTargetsMap[h] = append(hostTargetsMap[h], t)
	}

	// 收集所有 host 并排序
	allHosts := make([]string, 0, len(hostTargetsMap))
	for h := range hostTargetsMap {
		allHosts = append(allHosts, h)
	}
	sort.Strings(allHosts)

	totalHosts := len(allHosts)

	// 分页
	start := (page - 1) * pageSize
	if start >= totalHosts {
		c.JSON(http.StatusOK, gin.H{"data": []HostProfile{}, "page": page, "page_size": pageSize, "total": totalHosts})
		return
	}
	end := start + pageSize
	if end > totalHosts {
		end = totalHosts
	}
	pagedHosts := allHosts[start:end]

	// 收集当前页所有 host 对应的 targets
	var pagedTargets []string
	for _, h := range pagedHosts {
		pagedTargets = append(pagedTargets, hostTargetsMap[h]...)
	}
	if len(pagedTargets) == 0 {
		c.JSON(http.StatusOK, gin.H{"data": []HostProfile{}, "page": page, "page_size": pageSize, "total": totalHosts})
		return
	}

	// 步骤 3: 批量查询关联数据（含租户隔离 + 项目隔离），限制单页详情数量避免 OOM
	const profileDetailLimit = 1000

	type targetCount struct {
		Target string
		Count  int64
	}

	countByTarget := func(model interface{}, targets []string) map[string]int64 {
		q := db.DB.Model(model).Select("target, COUNT(*) as count").Where("target IN ?", targets)
		if tenantID != "" {
			q = q.Where("tenant_id = ?", tenantID)
		}
		q, _ = applyProjectScope(c, q, "project_id")
		var rows []targetCount
		if err := q.Group("target").Scan(&rows).Error; err != nil {
			log.Printf("[Profiles] failed to count targets for %T: %v", model, err)
			return map[string]int64{}
		}
		m := make(map[string]int64, len(rows))
		for _, r := range rows {
			m[r.Target] = r.Count
		}
		return m
	}

	assetCounts := countByTarget(&db.Asset{}, pagedTargets)
	fpCounts := countByTarget(&db.FingerprintHit{}, pagedTargets)
	vulnCounts := countByTarget(&db.Vulnerability{}, pagedTargets)

	var assets []db.Asset
	assocQ := db.DB.Where("target IN ?", pagedTargets)
	if tenantID != "" {
		assocQ = assocQ.Where("tenant_id = ?", tenantID)
	}
	assocQ, _ = applyProjectScope(c, assocQ, "project_id")
	assocQ.Order("created_at desc").Limit(profileDetailLimit).Find(&assets)

	var fps []db.FingerprintHit
	fpQ := db.DB.Where("target IN ?", pagedTargets)
	if tenantID != "" {
		fpQ = fpQ.Where("tenant_id = ?", tenantID)
	}
	fpQ, _ = applyProjectScope(c, fpQ, "project_id")
	fpQ.Order("created_at desc").Limit(profileDetailLimit).Find(&fps)

	var vulns []db.Vulnerability
	vulnQ := db.DB.Where("target IN ?", pagedTargets)
	if tenantID != "" {
		vulnQ = vulnQ.Where("tenant_id = ?", tenantID)
	}
	vulnQ, _ = applyProjectScope(c, vulnQ, "project_id")
	vulnQ.Order("created_at desc").Limit(profileDetailLimit).Find(&vulns)

	// 步骤 4: 按 host 聚合
	profiles := make([]HostProfile, 0, len(pagedHosts))
	for _, host := range pagedHosts {
		hp := HostProfile{Host: host}
		targets := hostTargetsMap[host]
		targetSet := make(map[string]bool, len(targets))
		for _, t := range targets {
			targetSet[t] = true
			if c, ok := assetCounts[t]; ok {
				hp.AssetCount += c
			}
			if c, ok := fpCounts[t]; ok {
				hp.FingerprintCount += c
			}
			if c, ok := vulnCounts[t]; ok {
				hp.VulnCount += c
			}
		}

		// 聚合端口信息：按端口号跨阶段合并（同一 ip:port 的 PortScan/Nmap/Web 行合成一行）
		portByNum := make(map[int]*PortInfo)
		var portOrder []int
		for _, a := range assets {
			if !targetSet[a.Target] {
				continue
			}
			hp.Assets = append(hp.Assets, a)

			resolvedPort := resolvePortForAsset(a)
			if resolvedPort == 0 {
				continue
			}

			transport, statusCode := parseService(a)
			info, exists := portByNum[resolvedPort]
			if !exists {
				info = &PortInfo{Port: resolvedPort, Transport: transport, Service: a.Service, StatusCode: statusCode, Title: a.Title, URL: a.URL}
				portByNum[resolvedPort] = info
				portOrder = append(portOrder, resolvedPort)
			} else {
				// Title/URL 取带 URL 的（Web）行；Service 取质量更高者；状态码优先非零。
				if a.URL != "" {
					if info.URL == "" || info.Title == "" {
						if a.Title != "" {
							info.Title = a.Title
						}
						info.URL = a.URL
					}
				} else if info.Title == "" && a.Title != "" {
					info.Title = a.Title
				}
				if serviceRank(a.Service) > serviceRank(info.Service) {
					info.Service = a.Service
				}
				if info.StatusCode == 0 && statusCode != 0 {
					info.StatusCode = statusCode
					if info.Transport == "" || info.Transport == "tcp" {
						info.Transport = transport
					}
				}
			}
			// Stages 去重保序、AssetIDs 收集（一行资产只记一次）
			stageSeen := false
			for _, s := range info.Stages {
				if s == a.Protocol {
					stageSeen = true
					break
				}
			}
			if !stageSeen {
				info.Stages = append(info.Stages, a.Protocol)
			}
			info.AssetIDs = append(info.AssetIDs, a.ID)
		}
		for _, p := range portOrder {
			hp.Ports = append(hp.Ports, *portByNum[p])
		}

		for _, f := range fps {
			if targetSet[f.Target] {
				hp.Fingerprints = append(hp.Fingerprints, f)
			}
		}
		for _, v := range vulns {
			if targetSet[v.Target] {
				hp.Vulns = append(hp.Vulns, v)
			}
		}

		// 端口排序
		sort.Slice(hp.Ports, func(i, j int) bool { return hp.Ports[i].Port < hp.Ports[j].Port })
		profiles = append(profiles, hp)
	}

	c.JSON(http.StatusOK, gin.H{"data": profiles, "page": page, "page_size": pageSize, "total": totalHosts})
}

func exportVulns(c *gin.Context) {
	var vulns []db.Vulnerability
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.Vulnerability{}).Where("tenant_id = ?", tenantID)
	query = applyReportResultScope(c, query, reportResultVulnerability)
	query.Find(&vulns)

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	_ = writer.Write([]string{"TenantID", "ProjectID", "TaskID", "Target", "Plugin", "Severity", "DetectedAt"})
	for _, v := range vulns {
		_ = writer.Write([]string{v.TenantID, v.ProjectID, v.TaskID, v.Target, v.Plugin, v.Severity, v.CreatedAt.Format(time.RFC3339)})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	recordReportExport(c, tenantID, "vulnerabilities", "vulnerabilities.csv", buf.Bytes())

	c.Writer.Header().Set("Content-Type", "text/csv")
	c.Writer.Header().Set("Content-Disposition", "attachment;filename=vulnerabilities.csv")
	c.Data(http.StatusOK, "text/csv", buf.Bytes())
}

func exportAssets(c *gin.Context) {
	var assets []db.Asset
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.Asset{}).Where("tenant_id = ?", tenantID)
	query = applyReportResultScope(c, query, reportResultAsset)
	query, err := applyAssetKindFilter(query, c.Query("kind"))
	if err != nil {
		if errors.Is(err, errUnknownAssetKind) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	query.Find(&assets)

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	_ = writer.Write([]string{"TenantID", "ProjectID", "TaskID", "Target", "Protocol", "Port", "URL", "Title", "Service", "DetectedAt"})
	for _, a := range assets {
		_ = writer.Write([]string{a.TenantID, a.ProjectID, a.TaskID, a.Target, a.Protocol, strconv.Itoa(a.Port), a.URL, a.Title, a.Service, a.CreatedAt.Format(time.RFC3339)})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	recordReportExport(c, tenantID, "assets", "assets.csv", buf.Bytes())

	c.Writer.Header().Set("Content-Type", "text/csv")
	c.Writer.Header().Set("Content-Disposition", "attachment;filename=assets.csv")
	c.Data(http.StatusOK, "text/csv", buf.Bytes())
}

func exportFingerprints(c *gin.Context) {
	var fps []db.FingerprintHit
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.FingerprintHit{}).Where("tenant_id = ?", tenantID)
	query = applyReportResultScope(c, query, reportResultFingerprint)
	query = applyFingerprintResultFilters(query, c.Query("search"), c.Query("source"))
	query.Find(&fps)

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	_ = writer.Write([]string{"TenantID", "ProjectID", "TaskID", "Target", "MatchedURL", "ProductName", "RuleName", "Source", "SourceLabel", "DetectedAt"})
	for _, f := range fps {
		source := db.ClassifyFingerprintSource(f.RuleName, f.Evidence)
		_ = writer.Write([]string{
			f.TenantID, f.ProjectID, f.TaskID, f.Target, db.FingerprintMatchedURL(f.Target, f.Evidence),
			f.ProductName, f.RuleName, source, db.FingerprintSourceLabel(source), f.CreatedAt.Format(time.RFC3339),
		})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	recordReportExport(c, tenantID, "fingerprints", "fingerprints.csv", buf.Bytes())

	c.Writer.Header().Set("Content-Type", "text/csv")
	c.Writer.Header().Set("Content-Disposition", "attachment;filename=fingerprints.csv")
	c.Data(http.StatusOK, "text/csv", buf.Bytes())
}

type reportResultKind uint8

const (
	reportResultVulnerability reportResultKind = iota
	reportResultAsset
	reportResultFingerprint
)

type reportResultReuseSource struct {
	SourceAttemptID string
	Target          string
	AttemptStatus   string
}

func applyReportResultScope(c *gin.Context, query *gorm.DB, kind reportResultKind) *gorm.DB {
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := strings.TrimSpace(c.Query("task_id")); taskID != "" {
		query = applyTaskResultScope(c, query, taskID, kind)
	}
	return query
}

func applyTaskResultScope(c *gin.Context, query *gorm.DB, taskID string, kind reportResultKind) *gorm.DB {
	scopedTaskIDs := resolveAccessibleTaskIDs(c, taskID)
	if len(scopedTaskIDs) == 0 {
		return query.Where("1 = 0")
	}
	taskScope := db.DB.Where("task_id IN ?", scopedTaskIDs)
	if kind == reportResultVulnerability {
		return query.Where(taskScope)
	}

	tenantID := currentTenantID(c)
	var root db.RootTask
	if err := db.DB.Select("id", "project_id").Where("id = ? AND tenant_id = ?", taskID, tenantID).First(&root).Error; err != nil {
		return query.Where(taskScope)
	}

	stages := []string{string(scanplan.StageFingerprint)}
	if kind == reportResultAsset {
		stages = []string{
			string(scanplan.StageSubdomainDiscovery),
			string(scanplan.StageCDNClassification), string(scanplan.StageICMPDiscovery),
			string(scanplan.StageTCPLiveness), string(scanplan.StagePortScan),
			string(scanplan.StageProtocolIdentify), string(scanplan.StageHTTPProbe),
			string(scanplan.StageHostBinding), string(scanplan.StageDirectoryProbe),
		}
	}
	var sources []reportResultReuseSource
	if err := db.DB.WithContext(c.Request.Context()).Table("task_coverage_links AS l").Distinct().
		Select("l.source_attempt_id, c.normalized_target AS target, source.status AS attempt_status").
		Joins("JOIN scan_coverages AS c ON c.id = l.coverage_id AND c.tenant_id = l.tenant_id AND c.project_id = l.project_id").
		Joins("JOIN sub_tasks AS source ON source.id = l.source_attempt_id AND source.tenant_id = l.tenant_id AND source.project_id = l.project_id AND source.root_task_id = l.source_task_id").
		Where("l.tenant_id = ? AND l.project_id = ? AND l.root_task_id = ? AND l.link_type = ? AND l.status = ?", tenantID, root.ProjectID, root.ID, "reused", "active").
		Where("c.stage IN ? AND c.status = ?", stages, string(scanplan.CoverageComplete)).
		Where("c.source_task_id = l.source_task_id AND c.source_batch_id = l.source_batch_id AND c.source_attempt_id = l.source_attempt_id").
		Where("c.valid_until IS NULL OR c.valid_until > ?", time.Now().UTC()).
		Scan(&sources).Error; err != nil {
		log.Printf("[Results] failed to load reusable result scope for task %s: %v", taskID, err)
		return query.Where(taskScope)
	}
	seen := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		if db.CanonicalAttemptState(source.AttemptStatus) != db.AttemptStateCompleted {
			continue
		}
		source.SourceAttemptID = strings.TrimSpace(source.SourceAttemptID)
		source.Target = strings.TrimSpace(source.Target)
		if source.SourceAttemptID == "" || source.Target == "" {
			continue
		}
		key := source.SourceAttemptID + "\x00" + source.Target
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		taskScope = taskScope.Or("task_id = ? AND target = ?", source.SourceAttemptID, source.Target)
	}
	return query.Where(taskScope)
}

func recordReportExport(c *gin.Context, tenantID, reportType, fileName string, content []byte) {
	store, err := storage.NewLocalStore(routerRuntime().ObjectStorageRoot)
	if err != nil {
		log.Printf("[Report] storage unavailable: %v", err)
		return
	}
	now := time.Now().UTC()
	key := fmt.Sprintf("reports/%s/%s-%s.csv", tenantID, reportType, now.Format("20060102T150405Z"))
	obj, err := store.Put(c.Request.Context(), key, bytes.NewReader(content))
	if err != nil {
		log.Printf("[Report] failed to persist export %s: %v", key, err)
		return
	}
	report := db.Report{
		ID:        fmt.Sprintf("%s:%d", tenantID, now.UnixNano()),
		ProjectID: strings.TrimSpace(c.Query("project_id")),
		Name:      fileName,
		Type:      reportType,
		Format:    "csv",
		FileURL:   "local://" + obj.Key,
		Status:    "ready",
		CreatedBy: currentUserID(c),
		CreatedAt: now,
	}
	if err := db.DB.Create(&report).Error; err != nil {
		log.Printf("[Report] failed to record export metadata %s: %v", report.ID, err)
	}
}

func getVulns(c *gin.Context) {
	var vulns []db.Vulnerability
	tenantID := currentTenantID(c)
	query := db.DB.Where("tenant_id = ?", tenantID)
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := c.Query("task_id"); taskID != "" {
		query = applyTaskResultScope(c, query, taskID, reportResultVulnerability)
	}
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		query = applyVulnSearch(query, search)
	}
	query = applyCSVResultFilter(query, "severity", c.Query("severity"), true)
	query = applyCSVResultFilter(query, "plugin", c.Query("plugin"), false)
	query = applyCSVResultFilter(query, "ai_status", c.Query("ai_status"), true)
	query = applyCSVResultFilter(query, "status", c.Query("status"), true)
	query = applyCSVResultFilter(query, "host", c.Query("host"), false)
	if ports := parseCSVPorts(c.Query("port")); len(ports) > 0 {
		query = query.Where("port IN ?", ports)
	}
	query = applyResultSort(c, query, "created_at", map[string]string{
		"severity":   "severity",
		"created_at": "created_at",
		"updated_at": "updated_at",
		"target":     "target",
		"plugin":     "plugin",
		"status":     "status",
		"ai_status":  "ai_status",
		"matched_at": "matched_at",
	})
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.Vulnerability{}, &vulns)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, pagedResponse(vulns, total, page, pageSize, ""))
}

// applyVulnSearch 做漏洞跨列自由文本模糊匹配（同一 term）。plugin≈nuclei
// template-id≈CVE，覆盖 CVE 检索；host 列为 Feature 新增的主机过滤维度。
// 用显式括号把 OR 组聚合，与后续 AND 过滤正确分组。
func applyVulnSearch(query *gorm.DB, search string) *gorm.DB {
	term := "%" + strings.TrimSpace(search) + "%"
	return query.Where(
		"(target LIKE ? OR plugin LIKE ? OR description LIKE ? OR host LIKE ?)",
		term, term, term, term,
	)
}

// applyAssetSearch 做资产跨列自由文本模糊匹配（同一 term）：目标/URL/标题/服务。
// 单表查询，列名无歧义，无需限定表前缀。括号聚合 OR 组，与后续 AND 过滤正确分组。
func applyAssetSearch(query *gorm.DB, search string) *gorm.DB {
	term := "%" + strings.TrimSpace(search) + "%"
	return query.Where(
		"(target LIKE ? OR url LIKE ? OR title LIKE ? OR service LIKE ?)",
		term, term, term, term,
	)
}

// parseCSVPorts 把逗号分隔的端口串解析成 int 切片，忽略空项与非法项。
// port 为整数列，单独解析为 int 绑定，避免 int vs text 绑定类型问题。
func parseCSVPorts(raw string) []int {
	var ports []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if pv, err := strconv.Atoi(part); err == nil && pv >= 0 && pv <= 65535 {
			ports = append(ports, pv)
		}
	}
	return ports
}

// applyCSVResultFilter 按列做逗号分隔多值过滤。raw 形如 "a,b,!c"：普通项为包含
// （IN），"!" 前缀项为排除（<>）。lower=true 时对列与取值套 LOWER()，用于大小写
// 不敏感的枚举列（severity/status/ai_status）；插件名等标识列传 false 保持精确匹配。
// 漏洞列表服务端分页，必须由数据库过滤，避免客户端只对当前页过滤导致总数/分页错乱。
// column 只能由调用点硬编码传入，不得取自用户输入，无注入面。
func applyCSVResultFilter(query *gorm.DB, column, raw string, lower bool) *gorm.DB {
	var include, exclude []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "!") {
			if negated := strings.TrimSpace(strings.TrimPrefix(part, "!")); negated != "" {
				exclude = append(exclude, negated)
			}
			continue
		}
		include = append(include, part)
	}
	col := column
	if lower {
		col = "LOWER(" + column + ")"
		for i := range include {
			include[i] = strings.ToLower(include[i])
		}
		for i := range exclude {
			exclude[i] = strings.ToLower(exclude[i])
		}
	}
	if len(include) > 0 {
		query = query.Where(col+" IN ?", include)
	}
	for _, value := range exclude {
		query = query.Where(col+" <> ?", value)
	}
	return query
}

// applyAssetFingerprintFilter 按指纹产品名过滤资产。raw 形如 "Apache,!Nginx"：
// 普通项为「资产关联了这些产品」，"!" 前缀项为「排除关联了这些产品的资产」。
// 资产↔指纹的权威关联在 Go 端按 endpointIdentity(host|port)+key 扩展计算
// （attachAssetFingerprints），无法纯 SQL 复刻；此处用子查询做直连匹配
// （assets.target/url = fingerprint_hits.target），覆盖标准 web 关联，
// 跨主机 retarget 别名（CDN/RealIP 交叉引用）可能漏——作为收窄过滤可接受。
// 子查询套 tenant+project+task 三层作用域，不越权；值走 ? 绑定，无注入面。
// 外表列必须限定 assets. 前缀，避免与子查询里的 target 列歧义。
func applyAssetFingerprintFilter(c *gin.Context, query *gorm.DB, raw string) *gorm.DB {
	var include, exclude []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "!") {
			if negated := strings.TrimSpace(strings.TrimPrefix(part, "!")); negated != "" {
				exclude = append(exclude, negated)
			}
			continue
		}
		include = append(include, part)
	}
	if len(include) == 0 && len(exclude) == 0 {
		return query
	}
	subquery := func(values []string) *gorm.DB {
		fp := db.DB.Model(&db.FingerprintHit{}).Select("target").Where("tenant_id = ?", currentTenantID(c))
		fp, _ = applyProjectScope(c, fp, "project_id")
		if taskID := strings.TrimSpace(c.Query("task_id")); taskID != "" {
			fp = applyTaskResultScope(c, fp, taskID, reportResultFingerprint)
		}
		return fp.Where("product_name IN ?", values)
	}
	if len(include) > 0 {
		// 每个占位符用独立子查询实例，避免同一 *gorm.DB 复用的共享状态问题。
		query = query.Where("assets.target IN (?) OR assets.url IN (?)", subquery(include), subquery(include))
	}
	for _, value := range exclude {
		query = query.Where("assets.target NOT IN (?) AND assets.url NOT IN (?)", subquery([]string{value}), subquery([]string{value}))
	}
	return query
}

// getVuln 返回单条漏洞全量字段（含 Request/Response 证据包），供结果详情查询。
// 访问收敛：requireProjectAccess + tenant + project + id。
func getVuln(c *gin.Context) {
	project, ok := requireProjectAccess(c, strings.TrimSpace(c.Query("project_id")))
	if !ok {
		return
	}
	var vuln db.Vulnerability
	if err := db.DB.Where("tenant_id = ? AND project_id = ? AND id = ?", currentTenantID(c), project.ID, c.Param("id")).First(&vuln).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vulnerability not found"})
		return
	}
	c.JSON(http.StatusOK, vuln)
}

// getVulnFacets 返回漏洞列表过滤维度（插件/状态/AI 研判）的 distinct 值与计数，
// 供前端过滤下拉填充选项。作用域与 getVulns 一致（租户 + 项目 + 任务 + 搜索
// + severity 视图），任务取自路径 :id，保证选项与列表数据对齐；空值不计入选项。
func getVulnFacets(c *gin.Context) {
	tenantID := currentTenantID(c)
	base := func() *gorm.DB {
		query := db.DB.Model(&db.Vulnerability{}).Where("tenant_id = ?", tenantID)
		query, _ = applyProjectScope(c, query, "project_id")
		query = applyTaskResultScope(c, query, c.Param("id"), reportResultVulnerability)
		if search := strings.TrimSpace(c.Query("search")); search != "" {
			query = applyVulnSearch(query, search)
		}
		return applyCSVResultFilter(query, "severity", c.Query("severity"), true)
	}
	type facetItem struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	}
	load := func(column string) []facetItem {
		// 初始化为非空切片，保证空结果序列化为 [] 而非 null，
		// 前端 .map 渲染选项不会因 null 抛 TypeError。
		items := []facetItem{}
		err := base().
			Select(column + " AS value, COUNT(*) AS count").
			Where(column + " <> ''").
			Group(column).
			Order("count DESC").
			Scan(&items).Error
		if err != nil {
			log.Printf("[Results] vuln facets %s failed: %v", column, err)
			return []facetItem{}
		}
		return items
	}
	// port 为整数列，不能套用 "<> ''" 文本谓词，单独按 port>0 分组计数。
	loadPorts := func() []facetItem {
		var rows []struct {
			Value int   `gorm:"column:value"`
			Count int64 `gorm:"column:count"`
		}
		if err := base().
			Select("port AS value, COUNT(*) AS count").
			Where("port > 0").
			Group("port").
			Order("count DESC").
			Scan(&rows).Error; err != nil {
			log.Printf("[Results] vuln facets port failed: %v", err)
			return []facetItem{}
		}
		items := make([]facetItem, 0, len(rows))
		for _, r := range rows {
			items = append(items, facetItem{Value: strconv.Itoa(r.Value), Count: r.Count})
		}
		return items
	}
	c.JSON(http.StatusOK, gin.H{
		"plugins":     load("plugin"),
		"statuses":    load("status"),
		"ai_statuses": load("ai_status"),
		"hosts":       load("host"),
		"ports":       loadPorts(),
	})
}

// getAssetFacets 返回资产列表过滤维度（服务/指纹产品）的 distinct 值与计数，
// 供前端过滤下拉填充选项。作用域与 getAssets 对齐：租户 + 项目 + 任务(:id)
// + 跨列搜索 + kind 视图（kind 是资产的「视图」开关，对应漏洞的 severity 视图）。
// 指纹选项按 tenant+project+task 取全集，不随其它维度选择收缩（与漏洞 facets
// 口径一致）。空值初始化为 []，避免前端 .map 对 null 抛 TypeError。
func getAssetFacets(c *gin.Context) {
	tenantID := currentTenantID(c)
	type facetItem struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	}
	assetBase := func() *gorm.DB {
		query := db.DB.Model(&db.Asset{}).Where("tenant_id = ?", tenantID)
		query, _ = applyProjectScope(c, query, "project_id")
		query = applyTaskResultScope(c, query, c.Param("id"), reportResultAsset)
		if search := strings.TrimSpace(c.Query("search")); search != "" {
			query = applyAssetSearch(query, search)
		}
		return query
	}
	kind := strings.TrimSpace(c.Query("kind"))
	assetQuery, kindErr := applyAssetKindFilter(assetBase(), kind)
	if kindErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errUnknownAssetKind.Error()})
		return
	}
	services := []facetItem{}
	if err := withoutQueryOrder(assetQuery).
		Select("service AS value, COUNT(*) AS count").
		Where("service <> ''").
		Group("service").
		Order("count DESC").
		Scan(&services).Error; err != nil {
		log.Printf("[Results] asset facets service failed: %v", err)
		services = []facetItem{}
	}
	fp := db.DB.Model(&db.FingerprintHit{}).Where("tenant_id = ?", tenantID)
	fp, _ = applyProjectScope(c, fp, "project_id")
	fp = applyTaskResultScope(c, fp, c.Param("id"), reportResultFingerprint)
	fingerprints := []facetItem{}
	if err := withoutQueryOrder(fp).
		Select("product_name AS value, COUNT(*) AS count").
		Group("product_name").
		Order("count DESC").
		Scan(&fingerprints).Error; err != nil {
		log.Printf("[Results] asset facets fingerprint failed: %v", err)
		fingerprints = []facetItem{}
	}
	c.JSON(http.StatusOK, gin.H{
		"services":     services,
		"fingerprints": fingerprints,
	})
}

func getAssets(c *gin.Context) {
	var assets []db.Asset
	tenantID := currentTenantID(c)
	query := db.DB.Where("tenant_id = ?", tenantID).Order("created_at desc")
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := c.Query("task_id"); taskID != "" {
		query = applyTaskResultScope(c, query, taskID, reportResultAsset)
	}
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		query = applyAssetSearch(query, search)
	}
	query = applyCSVResultFilter(query, "service", c.Query("service"), false)
	query = applyCSVResultFilter(query, "title", c.Query("title"), false)
	query = applyAssetFingerprintFilter(c, query, c.Query("fingerprint"))
	stats, err := collectAssetResultStats(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	query, err = applyAssetKindFilter(query, c.Query("kind"))
	if err != nil {
		if errors.Is(err, errUnknownAssetKind) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.Asset{}, &assets)
	if !ok {
		return
	}
	items, err := attachAssetFingerprints(c, assets, stats.Resolutions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pagedResponseWithStats(items, total, page, pageSize, "", stats))
}

func getFingerprints(c *gin.Context) {
	var fps []db.FingerprintHit
	baseQuery := fingerprintResultQuery(c)
	if strings.EqualFold(strings.TrimSpace(c.Query("group_by")), "product") {
		getFingerprintGroups(c, baseQuery)
		return
	}
	query := baseQuery.Order("created_at desc")
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.FingerprintHit{}, &fps)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, pagedResponse(fps, total, page, pageSize, ""))
}

func fingerprintResultQuery(c *gin.Context) *gorm.DB {
	tenantID := currentTenantID(c)
	query := db.DB.Model(&db.FingerprintHit{}).Where("tenant_id = ?", tenantID)
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := c.Query("task_id"); taskID != "" {
		query = applyTaskResultScope(c, query, taskID, reportResultFingerprint)
	}
	return applyFingerprintResultFilters(query, c.Query("search"), c.Query("source"))
}

func applyFingerprintResultFilters(query *gorm.DB, search, source string) *gorm.DB {
	search = strings.TrimSpace(search)
	if search != "" {
		like := "%" + search + "%"
		query = query.Where("product_name LIKE ? OR target LIKE ? OR evidence LIKE ? OR rule_name LIKE ?", like, like, like, like)
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "directory", "active":
		query = query.Where(
			"(LOWER(COALESCE(rule_name, '')) IN ? OR LOWER(evidence) LIKE ? OR LOWER(evidence) LIKE ?) AND LOWER(COALESCE(rule_name, '')) NOT IN ? AND LOWER(evidence) NOT LIKE ? AND LOWER(evidence) NOT LIKE ?",
			[]string{"active-finger", "directory"},
			`%"type":"active-finger"%`,
			`%"type": "active-finger"%`,
			[]string{"dir-fallback", "behavior-probe"},
			`%[dir-fallback]%`,
			`%[behavior-probe:%`,
		)
	case "behavior":
		query = query.Where("LOWER(COALESCE(rule_name, '')) = ? OR LOWER(evidence) LIKE ?", "behavior-probe", `%[behavior-probe:%`)
	case "fallback":
		query = query.Where("LOWER(COALESCE(rule_name, '')) = ? OR LOWER(evidence) LIKE ?", "dir-fallback", `%[dir-fallback]%`)
	case "passive":
		query = query.Where(
			"LOWER(COALESCE(rule_name, '')) NOT IN ? AND LOWER(evidence) NOT LIKE ? AND LOWER(evidence) NOT LIKE ? AND LOWER(evidence) NOT LIKE ?",
			[]string{"active-finger", "directory", "dir-fallback", "behavior-probe"},
			`%"type":"active-finger"%`,
			`%[dir-fallback]%`,
			`%[behavior-probe:%`,
		)
	}
	return query
}

type fingerprintGroupTarget struct {
	Target      string
	MatchedURL  string
	RuleName    string
	Source      string
	SourceLabel string
	Evidence    string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type fingerprintGroup struct {
	ProductName  string
	TargetCount  int64
	Targets      []fingerprintGroupTarget
	Sources      []string
	SourceLabels []string
	FirstSeen    time.Time
	LastSeen     time.Time
}

func getFingerprintGroups(c *gin.Context, query *gorm.DB) {
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		query = query.Where("product_name LIKE ?", "%"+search+"%")
	}
	page, pageSize := parsePagination(c, 20, 200)
	totalQuery := query.Session(&gorm.Session{}).
		Select("product_name").
		Group("product_name")

	var total int64
	if err := db.DB.Table("(?) as grouped", totalQuery).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type groupRow struct {
		ProductName string
		TargetCount int64
	}
	rows := make([]groupRow, 0)
	if err := query.Session(&gorm.Session{}).
		Select("product_name, COUNT(*) as target_count").
		Group("product_name").
		Order("target_count DESC, product_name ASC").
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	productNames := make([]string, 0, len(rows))
	groupIndexByProduct := make(map[string]int, len(rows))
	groups := make([]fingerprintGroup, 0, len(rows))
	for _, row := range rows {
		group := fingerprintGroup{
			ProductName: row.ProductName,
			TargetCount: row.TargetCount,
			Targets:     make([]fingerprintGroupTarget, 0, int(row.TargetCount)),
		}
		groups = append(groups, group)
		groupIndexByProduct[row.ProductName] = len(groups) - 1
		productNames = append(productNames, row.ProductName)
	}

	if len(productNames) > 0 {
		hits := make([]db.FingerprintHit, 0)
		if err := query.Session(&gorm.Session{}).
			Where("product_name IN ?", productNames).
			Order("product_name ASC, target ASC, created_at ASC").
			Find(&hits).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, hit := range hits {
			groupIndex, ok := groupIndexByProduct[hit.ProductName]
			if !ok {
				continue
			}
			group := &groups[groupIndex]
			source := db.ClassifyFingerprintSource(hit.RuleName, hit.Evidence)
			group.Targets = append(group.Targets, fingerprintGroupTarget{
				Target:      hit.Target,
				MatchedURL:  db.FingerprintMatchedURL(hit.Target, hit.Evidence),
				RuleName:    hit.RuleName,
				Source:      source,
				SourceLabel: db.FingerprintSourceLabel(source),
				Evidence:    hit.Evidence,
				CreatedAt:   hit.CreatedAt,
				UpdatedAt:   hit.UpdatedAt,
			})
			group.Sources = append(group.Sources, source)
			if group.FirstSeen.IsZero() || hit.CreatedAt.Before(group.FirstSeen) {
				group.FirstSeen = hit.CreatedAt
			}
			if group.LastSeen.IsZero() || hit.UpdatedAt.After(group.LastSeen) {
				group.LastSeen = hit.UpdatedAt
			}
		}
		for i := range groups {
			groups[i].Sources = db.UniqueFingerprintSources(groups[i].Sources)
			groups[i].SourceLabels = db.FingerprintSourceLabels(groups[i].Sources)
		}
	}

	c.JSON(http.StatusOK, pagedResponseWithStats(groups, total, page, pageSize, "", fingerprintGroupStats(query)))
}

// fingerprintGroupStats aggregates hit counts over the same scoped (and
// search-filtered) query used for grouping, independent of pagination.
func fingerprintGroupStats(query *gorm.DB) struct {
	TotalHits       int64 `json:"total_hits"`
	DistinctTargets int64 `json:"distinct_targets"`
} {
	var stats struct {
		TotalHits       int64 `json:"total_hits"`
		DistinctTargets int64 `json:"distinct_targets"`
	}
	query.Session(&gorm.Session{}).Model(&db.FingerprintHit{}).
		Select("COUNT(*) AS total_hits, COUNT(DISTINCT target) AS distinct_targets").
		Scan(&stats)
	return stats
}

// applyResultSort applies an optional sort clause from query parameters.
// supported maps frontend sort field names to database column/expression names.
// For severity, it uses a CASE expression so the order reflects actual risk
// (critical > high > medium > low > info > unknown) instead of alphabetical.
func applyResultSort(c *gin.Context, query *gorm.DB, defaultField string, supported map[string]string) *gorm.DB {
	sortField := strings.TrimSpace(c.Query("sort"))
	if sortField == "" {
		sortField = defaultField
	}
	sortField = strings.ToLower(sortField)

	sortOrder := strings.ToLower(strings.TrimSpace(c.Query("order")))
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	column, ok := supported[sortField]
	if !ok {
		column = defaultField
	}

	if column == "severity" {
		return query.Order(fmt.Sprintf(
			"CASE LOWER(severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END %s",
			sortOrder,
		))
	}
	return query.Order(fmt.Sprintf("%s %s", column, sortOrder))
}

func paginateResultQuery(c *gin.Context, query *gorm.DB, model interface{}, dest interface{}) (int, int, int64, bool) {
	page, pageSize := parsePagination(c, 20, 200)
	var total int64
	if err := query.Session(&gorm.Session{}).Model(model).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return page, pageSize, 0, false
	}
	if err := query.Session(&gorm.Session{}).Limit(pageSize).Offset((page - 1) * pageSize).Find(dest).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return page, pageSize, total, false
	}
	return page, pageSize, total, true
}

package api

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/storage"
	"gorm.io/gorm"
)

// HostProfile 以主机(IP/域名)为单位聚合的画像
type HostProfile struct {
	Host         string              `json:"host"`
	Ports        []PortInfo          `json:"ports"`
	Assets       []db.Asset          `json:"assets"`
	Fingerprints []db.FingerprintHit `json:"fingerprints"`
	Vulns        []db.Vulnerability  `json:"vulns"`
}

type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Title    string `json:"title"`
	URL      string `json:"url"`
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

	// 步骤 3: 批量查询关联数据（含租户隔离 + 项目隔离）
	var assets []db.Asset
	assocQ := db.DB.Where("target IN ?", pagedTargets)
	if tenantID != "" {
		assocQ = assocQ.Where("tenant_id = ?", tenantID)
	}
	assocQ, _ = applyProjectScope(c, assocQ, "project_id")
	assocQ.Find(&assets)

	var fps []db.FingerprintHit
	fpQ := db.DB.Where("target IN ?", pagedTargets)
	if tenantID != "" {
		fpQ = fpQ.Where("tenant_id = ?", tenantID)
	}
	fpQ, _ = applyProjectScope(c, fpQ, "project_id")
	fpQ.Find(&fps)

	var vulns []db.Vulnerability
	vulnQ := db.DB.Where("target IN ?", pagedTargets)
	if tenantID != "" {
		vulnQ = vulnQ.Where("tenant_id = ?", tenantID)
	}
	vulnQ, _ = applyProjectScope(c, vulnQ, "project_id")
	vulnQ.Find(&vulns)

	// 步骤 4: 按 host 聚合
	profiles := make([]HostProfile, 0, len(pagedHosts))
	for _, host := range pagedHosts {
		hp := HostProfile{Host: host}
		targets := hostTargetsMap[host]
		targetSet := make(map[string]bool, len(targets))
		for _, t := range targets {
			targetSet[t] = true
		}

		// 聚合端口信息 (去重)
		portSeen := make(map[string]bool)
		for _, a := range assets {
			if !targetSet[a.Target] {
				continue
			}
			hp.Assets = append(hp.Assets, a)

			// 从 Asset.Port 或 Target 字符串中提取端口号
			resolvedPort := a.Port
			if resolvedPort == 0 && a.Target != "" {
				if u, err := url.Parse(a.Target); err == nil && u.Port() != "" {
					if pv, e := strconv.Atoi(u.Port()); e == nil {
						resolvedPort = pv
					}
				} else if _, portStr, err := net.SplitHostPort(a.Target); err == nil {
					if pv, e := strconv.Atoi(portStr); e == nil {
						resolvedPort = pv
					}
				}
			}

			portKey := fmt.Sprintf("%d:%s", resolvedPort, a.Protocol)
			if !portSeen[portKey] {
				portSeen[portKey] = true
				hp.Ports = append(hp.Ports, PortInfo{
					Port:     resolvedPort,
					Protocol: a.Protocol,
					Service:  a.Service,
					Title:    a.Title,
					URL:      a.URL,
				})
			}
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
	query = applyReportResultScope(c, query)
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
	query = applyReportResultScope(c, query)
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
	query = applyReportResultScope(c, query)
	query.Find(&fps)

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	_ = writer.Write([]string{"TenantID", "ProjectID", "TaskID", "Target", "ProductName", "RuleName", "DetectedAt"})
	for _, f := range fps {
		_ = writer.Write([]string{f.TenantID, f.ProjectID, f.TaskID, f.Target, f.ProductName, f.RuleName, f.CreatedAt.Format(time.RFC3339)})
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

func applyReportResultScope(c *gin.Context, query *gorm.DB) *gorm.DB {
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := strings.TrimSpace(c.Query("task_id")); taskID != "" {
		if scopedTaskIDs := resolveAccessibleTaskIDs(c, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		} else {
			query = query.Where("1 = 0")
		}
	}
	return query
}

func recordReportExport(c *gin.Context, tenantID, reportType, fileName string, content []byte) {
	store, err := storage.NewLocalStore(objectStorageRoot)
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
	query := db.DB.Where("tenant_id = ?", tenantID).Order("created_at desc")
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := c.Query("task_id"); taskID != "" {
		if scopedTaskIDs := resolveAccessibleTaskIDs(c, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		} else {
			query = query.Where("1 = 0")
		}
	}
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.Vulnerability{}, &vulns)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, pagedResponse(vulns, total, page, pageSize, ""))
}

func getAssets(c *gin.Context) {
	var assets []db.Asset
	tenantID := currentTenantID(c)
	query := db.DB.Where("tenant_id = ?", tenantID).Order("created_at desc")
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := c.Query("task_id"); taskID != "" {
		if scopedTaskIDs := resolveAccessibleTaskIDs(c, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		} else {
			query = query.Where("1 = 0")
		}
	}
	page, pageSize, total, ok := paginateResultQuery(c, query, &db.Asset{}, &assets)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, pagedResponse(assets, total, page, pageSize, ""))
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
		if scopedTaskIDs := resolveAccessibleTaskIDs(c, taskID); len(scopedTaskIDs) > 1 {
			query = query.Where("task_id IN ?", scopedTaskIDs)
		} else if len(scopedTaskIDs) == 1 {
			query = query.Where("task_id = ?", scopedTaskIDs[0])
		} else {
			query = query.Where("1 = 0")
		}
	}
	return query
}

type fingerprintGroupTarget struct {
	Target    string
	RuleName  string
	Evidence  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type fingerprintGroup struct {
	ProductName string
	TargetCount int64
	Targets     []fingerprintGroupTarget
	FirstSeen   time.Time
	LastSeen    time.Time
}

func getFingerprintGroups(c *gin.Context, query *gorm.DB) {
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
			group.Targets = append(group.Targets, fingerprintGroupTarget{
				Target:    hit.Target,
				RuleName:  hit.RuleName,
				Evidence:  hit.Evidence,
				CreatedAt: hit.CreatedAt,
				UpdatedAt: hit.UpdatedAt,
			})
			if group.FirstSeen.IsZero() || hit.CreatedAt.Before(group.FirstSeen) {
				group.FirstSeen = hit.CreatedAt
			}
			if group.LastSeen.IsZero() || hit.UpdatedAt.After(group.LastSeen) {
				group.LastSeen = hit.UpdatedAt
			}
		}
	}

	c.JSON(http.StatusOK, pagedResponse(groups, total, page, pageSize, ""))
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

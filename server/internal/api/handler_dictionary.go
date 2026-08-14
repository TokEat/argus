package api

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

type WorkflowEntry struct {
	Type []string `yaml:"type" json:"type"`
	Pocs []string `yaml:"pocs" json:"pocs"`
}

// WorkflowItem 是传递给前端进行编辑的完整实体结构
type WorkflowItem struct {
	Product string   `json:"product"`
	Type    []string `json:"type"`
	Pocs    []string `json:"pocs"`
}

func syncRuleCatalogAndBumpVersion() (string, error) {
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		return "", err
	}
	return BumpRuleVersion(), nil
}

// fetchAndParseWorkflow 获取并解析数据库中的 workflow.yaml 单体内容
func fetchAndParseWorkflow(tenantID string) (map[string]WorkflowEntry, *db.Arsenal, error) {
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, "workflow", "workflow.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("workflow dictionary not found in arsenal")
	}

	var data map[string]WorkflowEntry
	if err := yaml.Unmarshal([]byte(arsenal.Content), &data); err != nil {
		return nil, nil, fmt.Errorf("failed to parse yaml: %v", err)
	}

	if data == nil {
		data = make(map[string]WorkflowEntry)
	}
	return data, arsenal, nil
}

// saveWorkflow 序列化数据并覆盖保存回数据库
func saveWorkflow(data map[string]WorkflowEntry, arsenal *db.Arsenal) error {
	out, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	contentStr := string(out)
	hash := fmt.Sprintf("%x", md5.Sum(out))

	candidate := *arsenal
	candidate.Content = contentStr
	candidate.Hash = hash
	candidate.Version++
	if err := db.ValidateRuleCatalogCandidate(candidate); err != nil {
		return err
	}

	arsenal.Content = contentStr
	arsenal.Hash = hash
	arsenal.Version++
	if err := db.DB.Save(arsenal).Error; err != nil {
		return err
	}
	_, err = syncRuleCatalogAndBumpVersion()
	return err
}

func getWorkflowDict(c *gin.Context) {
	if c.Query("lite") == "1" || c.Query("page") != "" || c.Query("page_size") != "" {
		listWorkflowSummaries(c)
		return
	}

	data, _, err := fetchAndParseWorkflow(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	results := make([]WorkflowItem, 0, len(data))
	for k, v := range data {
		results = append(results, WorkflowItem{
			Product: k,
			Type:    v.Type,
			Pocs:    v.Pocs,
		})
	}

	c.JSON(http.StatusOK, results)
}

type workflowSummaryResponse struct {
	Product              string   `json:"product"`
	Type                 []string `json:"type"`
	Pocs                 []string `json:"pocs"`
	PocCount             int      `json:"poc_count"`
	MissingPocs          []string `json:"missing_pocs"`
	MissingPocCount      int      `json:"missing_poc_count"`
	FingerprintBound     bool     `json:"fingerprint_bound"`
	FingerprintRuleCount int      `json:"fingerprint_rule_count"`
	IsGeneralPoc         bool     `json:"is_general_poc"`
	State                string   `json:"state"`
	Enabled              bool     `json:"enabled"`
	ContentHash          string   `json:"content_hash"`
	Version              int      `json:"version"`
	UpdatedAt            string   `json:"updated_at"`
}

type workflowSummaryStatsResponse struct {
	Total              int64 `json:"total" gorm:"column:total"`
	FingerprintMissing int64 `json:"fp_missing" gorm:"column:fp_missing"`
	POCMissing         int64 `json:"poc_missing" gorm:"column:poc_missing"`
	TotalPOCs          int64 `json:"total_pocs" gorm:"column:total_pocs"`
	FingerprintRules   int64 `json:"fingerprint_rules" gorm:"column:fingerprint_rules"`
}

func listWorkflowSummaries(c *gin.Context) {
	tenantID := currentTenantID(c)
	page, pageSize := parsePagination(c, 50, 200)
	query := workflowSummaryQuery(c, tenantID)

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	stats, err := workflowSummaryStats(workflowSummaryQuery(c, tenantID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []db.WorkflowProductSummary
	if err := workflowSummaryQuery(c, tenantID).Order("product_name ASC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	items := make([]workflowSummaryResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, workflowSummaryToResponse(row))
	}
	c.JSON(http.StatusOK, pagedResponseWithStats(items, total, page, pageSize, currentRuleVersion(), stats))
}

func workflowSummaryQuery(c *gin.Context, tenantID string) *gorm.DB {
	query := db.DB.Model(&db.WorkflowProductSummary{}).Where("tenant_id = ?", tenantID)

	switch strings.ToLower(strings.TrimSpace(c.Query("scope"))) {
	case "general":
		query = query.Where("is_general_poc = ?", true)
	case "specific":
		query = query.Where("is_general_poc = ?", false)
	}

	switch strings.ToLower(strings.TrimSpace(c.Query("health"))) {
	case "fp_missing":
		query = query.Where("is_general_poc = ? AND fingerprint_bound = ?", false, false)
	case "poc_missing":
		query = query.Where("missing_poc_count > 0")
	case "healthy":
		query = query.Where("missing_poc_count = 0 AND (is_general_poc = true OR fingerprint_bound = true)")
	}

	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		query = query.Where("LOWER(product_name) LIKE ? OR LOWER(CAST(poc_names AS TEXT)) LIKE ? OR LOWER(CAST(match_types AS TEXT)) LIKE ?", like, like, like)
	}
	return query
}

func workflowSummaryStats(query *gorm.DB) (workflowSummaryStatsResponse, error) {
	var stats workflowSummaryStatsResponse
	err := query.Select(`
		COUNT(*) AS total,
		COALESCE(SUM(CASE WHEN is_general_poc = ? AND fingerprint_bound = ? THEN 1 ELSE 0 END), 0) AS fp_missing,
		COALESCE(SUM(CASE WHEN missing_poc_count > 0 THEN 1 ELSE 0 END), 0) AS poc_missing,
		COALESCE(SUM(poc_count), 0) AS total_pocs,
		COALESCE(SUM(fingerprint_rule_count), 0) AS fingerprint_rules
	`, false, false).Scan(&stats).Error
	return stats, err
}

func workflowSummaryToResponse(row db.WorkflowProductSummary) workflowSummaryResponse {
	return workflowSummaryResponse{
		Product:              row.ProductName,
		Type:                 jsonStringSlice(row.MatchTypes),
		Pocs:                 jsonStringSlice(row.PocNames),
		PocCount:             row.PocCount,
		MissingPocs:          jsonStringSlice(row.MissingPocNames),
		MissingPocCount:      row.MissingPocCount,
		FingerprintBound:     row.FingerprintBound,
		FingerprintRuleCount: row.FingerprintRuleCount,
		IsGeneralPoc:         row.IsGeneralPoc,
		State:                row.State,
		Enabled:              row.Enabled,
		ContentHash:          row.ContentHash,
		Version:              row.Version,
		UpdatedAt:            formatPocRuleTime(row.UpdatedAt),
	}
}

func addWorkflowDict(c *gin.Context) {
	var req WorkflowItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Product = strings.TrimSpace(req.Product)
	if req.Product == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product Name is required"})
		return
	}

	data, arsenal, err := fetchAndParseWorkflow(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[req.Product]; exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Product already exists"})
		return
	}

	data[req.Product] = WorkflowEntry{
		Type: req.Type,
		Pocs: req.Pocs,
	}

	if err := saveWorkflow(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "added", "product": req.Product})
}

func updateWorkflowDict(c *gin.Context) {
	product := c.Param("product")
	var req WorkflowItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	data, arsenal, err := fetchAndParseWorkflow(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	// 允许重命名键值
	req.Product = strings.TrimSpace(req.Product)
	if req.Product != "" && req.Product != product {
		// 如果更名了，需要确保新名字不冲突
		if _, exists := data[req.Product]; exists {
			c.JSON(http.StatusConflict, gin.H{"error": "New Product Name already exists"})
			return
		}
		delete(data, product)
		product = req.Product
	}

	data[product] = WorkflowEntry{
		Type: req.Type,
		Pocs: req.Pocs,
	}

	if err := saveWorkflow(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated", "product": product})
}

func deleteWorkflowDict(c *gin.Context) {
	product := c.Param("product")

	data, arsenal, err := fetchAndParseWorkflow(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	delete(data, product)

	if err := saveWorkflow(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted", "product": product})
}

// ---------------------- Fingerprint ----------------------

type FingerprintItem struct {
	Product string   `json:"product"`
	Rules   []string `json:"rules"` // 在 yaml 中直接对应字符串数组
}

// fetchAndParseFingerprint 获取并解析数据库中的 finger.yaml 单体内容
func fetchAndParseFingerprint(tenantID string) (map[string][]string, *db.Arsenal, error) {
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, "finger", "finger.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("fingerprint dictionary not found in arsenal")
	}

	var data map[string][]string
	if err := yaml.Unmarshal([]byte(arsenal.Content), &data); err != nil {
		return nil, nil, fmt.Errorf("failed to parse yaml: %v", err)
	}

	if data == nil {
		data = make(map[string][]string)
	}
	return data, arsenal, nil
}

func saveFingerprint(data map[string][]string, arsenal *db.Arsenal) error {
	out, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	contentStr := string(out)
	hash := fmt.Sprintf("%x", md5.Sum(out))

	candidate := *arsenal
	candidate.Content = contentStr
	candidate.Hash = hash
	candidate.Version++
	if err := db.ValidateRuleCatalogCandidate(candidate); err != nil {
		return err
	}

	arsenal.Content = contentStr
	arsenal.Hash = hash
	arsenal.Version++

	if err := db.DB.Save(arsenal).Error; err != nil {
		return err
	}
	_, err = syncRuleCatalogAndBumpVersion()
	return err
}

func getFingerprintDict(c *gin.Context) {
	if c.Query("lite") == "1" || c.Query("page") != "" || c.Query("page_size") != "" {
		listFingerprintSummaries(c)
		return
	}

	tenantID := currentTenantID(c)
	data, _, parseErr := fetchAndParseFingerprint(tenantID)
	if parseErr != nil {
		data = make(map[string][]string)
	}

	var structuredRules []db.FingerprintRule
	if err := db.DB.Where("tenant_id = ? AND enabled = ?", tenantID, true).
		Order("product_name ASC, rule_expr ASC").
		Find(&structuredRules).Error; err != nil {
		if len(data) == 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		for _, row := range structuredRules {
			productName := strings.TrimSpace(row.ProductName)
			ruleExpr := strings.TrimSpace(row.RuleExpr)
			if productName == "" || ruleExpr == "" {
				continue
			}
			existing := data[productName]
			duplicate := false
			for _, rule := range existing {
				if strings.TrimSpace(rule) == ruleExpr {
					duplicate = true
					break
				}
			}
			if !duplicate {
				data[productName] = append(existing, ruleExpr)
			}
		}
	}
	if parseErr != nil && len(data) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": parseErr.Error()})
		return
	}

	results := make([]FingerprintItem, 0, len(data))
	for k, v := range data {
		results = append(results, FingerprintItem{
			Product: k,
			Rules:   v,
		})
	}
	c.JSON(http.StatusOK, results)
}

type fingerprintSummaryResponse struct {
	Product   string   `json:"product"`
	Rules     []string `json:"rules,omitempty"`
	RuleCount int      `json:"rule_count"`
	State     string   `json:"state"`
	Enabled   bool     `json:"enabled"`
	Version   int      `json:"version"`
	UpdatedAt string   `json:"updated_at"`
}

func listFingerprintSummaries(c *gin.Context) {
	tenantID := currentTenantID(c)
	page, pageSize := parsePagination(c, 50, 200)
	includeRules := c.Query("include_rules") == "1"

	query := db.DB.Model(&db.FingerprintRule{}).Where("tenant_id = ?", tenantID)
	if c.Query("all") != "1" {
		query = query.Where("enabled = ?", true)
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		query = query.Where("LOWER(product_name) LIKE ?", "%"+strings.ToLower(q)+"%")
	}

	type groupedFingerprint struct {
		ProductName string
		RuleCount   int
		State       string
		Enabled     bool
		Version     int
		UpdatedAt   time.Time
	}
	grouped := db.DB.Table("(?) as fp", query.Select("product_name, rule_expr, state, enabled, version, updated_at")).
		Select("product_name, COUNT(*) AS rule_count, MAX(state) AS state, BOOL_OR(enabled) AS enabled, MAX(version) AS version, MAX(updated_at) AS updated_at").
		Group("product_name")

	var total int64
	if err := db.DB.Table("(?) as grouped", grouped).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var rows []groupedFingerprint
	if err := grouped.Order("product_name ASC").Limit(pageSize).Offset((page - 1) * pageSize).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	items := make([]fingerprintSummaryResponse, 0, len(rows))
	includeDisabled := c.Query("all") == "1"
	for _, row := range rows {
		item := fingerprintSummaryResponse{
			Product:   row.ProductName,
			RuleCount: row.RuleCount,
			State:     row.State,
			Enabled:   row.Enabled,
			Version:   row.Version,
			UpdatedAt: formatPocRuleTime(row.UpdatedAt),
		}
		if includeRules {
			rules, err := loadFingerprintSummaryRules(tenantID, row.ProductName, includeDisabled)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			item.Rules = rules
		}
		items = append(items, item)
	}
	c.JSON(http.StatusOK, pagedResponse(items, total, page, pageSize, currentRuleVersion()))
}

func loadFingerprintSummaryRules(tenantID, productName string, includeDisabled bool) ([]string, error) {
	query := db.DB.Model(&db.FingerprintRule{}).
		Where("tenant_id = ? AND product_name = ?", tenantID, productName)
	if !includeDisabled {
		query = query.Where("enabled = ?", true)
	}
	var rules []string
	if err := query.Order("rule_expr ASC").Pluck("rule_expr", &rules).Error; err != nil {
		return nil, err
	}
	return rules, nil
}

func jsonStringSlice(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return []string{}
	}
	return out
}

func addFingerprintDict(c *gin.Context) {
	var req FingerprintItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Product = strings.TrimSpace(req.Product)
	if req.Product == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product Name is required"})
		return
	}

	data, arsenal, err := fetchAndParseFingerprint(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[req.Product]; exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Product already exists"})
		return
	}

	data[req.Product] = req.Rules
	if err := saveFingerprint(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "added", "product": req.Product})
}

func updateFingerprintDict(c *gin.Context) {
	product := c.Param("product")
	var req FingerprintItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	data, arsenal, err := fetchAndParseFingerprint(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	req.Product = strings.TrimSpace(req.Product)
	if req.Product != "" && req.Product != product {
		if _, exists := data[req.Product]; exists {
			c.JSON(http.StatusConflict, gin.H{"error": "New Product Name already exists"})
			return
		}
		references, err := fingerprintProductReferences(currentTenantID(c), product)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if len(references) > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": fingerprintReferenceConflict(product, references).Error()})
			return
		}
		delete(data, product)
		product = req.Product
	}

	data[product] = req.Rules
	if err := saveFingerprint(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated", "product": product})
}

func deleteFingerprintDict(c *gin.Context) {
	product := c.Param("product")
	data, arsenal, err := fetchAndParseFingerprint(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}
	references, err := fingerprintProductReferences(currentTenantID(c), product)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(references) > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": fingerprintReferenceConflict(product, references).Error()})
		return
	}

	delete(data, product)
	if err := saveFingerprint(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted", "product": product})
}

// ---------------------- Dir Probe ----------------------

type DirItem struct {
	Product string   `json:"product"`
	Paths   []string `json:"paths"`
}

func fetchAndParseDir(tenantID string) (map[string][]string, *db.Arsenal, error) {
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, "dir", "dir.yaml")
	if err != nil {
		return nil, nil, fmt.Errorf("dir dictionary not found in arsenal")
	}

	var data map[string][]string
	if err := yaml.Unmarshal([]byte(arsenal.Content), &data); err != nil {
		return nil, nil, fmt.Errorf("failed to parse yaml: %v", err)
	}

	if data == nil {
		data = make(map[string][]string)
	}
	return data, arsenal, nil
}

func saveDir(data map[string][]string, arsenal *db.Arsenal) error {
	out, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	contentStr := string(out)
	hash := fmt.Sprintf("%x", md5.Sum(out))
	candidate := *arsenal
	candidate.Content = contentStr
	candidate.Hash = hash
	candidate.Version++
	if err := db.ValidateRuleCatalogCandidate(candidate); err != nil {
		return err
	}

	arsenal.Content = contentStr
	arsenal.Hash = hash
	arsenal.Version++

	if err := db.DB.Save(arsenal).Error; err != nil {
		return err
	}
	_, err = syncRuleCatalogAndBumpVersion()
	return err
}

func getDirDict(c *gin.Context) {
	data, _, err := fetchAndParseDir(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var results []DirItem
	for k, v := range data {
		results = append(results, DirItem{
			Product: k,
			Paths:   v,
		})
	}
	c.JSON(http.StatusOK, results)
}

func addDirDict(c *gin.Context) {
	var req DirItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Product = strings.TrimSpace(req.Product)
	if req.Product == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Product Name is required"})
		return
	}
	paths, err := normalizeDirPaths(req.Paths)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Paths = paths

	data, arsenal, err := fetchAndParseDir(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[req.Product]; exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Product already exists"})
		return
	}

	data[req.Product] = req.Paths
	if err := saveDir(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "added", "product": req.Product})
}

func updateDirDict(c *gin.Context) {
	product := c.Param("product")
	var req DirItem
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	data, arsenal, err := fetchAndParseDir(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}
	paths, err := normalizeDirPaths(req.Paths)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Paths = paths

	req.Product = strings.TrimSpace(req.Product)
	if req.Product != "" && req.Product != product {
		if _, exists := data[req.Product]; exists {
			c.JSON(http.StatusConflict, gin.H{"error": "New Product Name already exists"})
			return
		}
		delete(data, product)
		product = req.Product
	}

	data[product] = req.Paths
	if err := saveDir(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated", "product": product})
}

func deleteDirDict(c *gin.Context) {
	product := c.Param("product")
	data, arsenal, err := fetchAndParseDir(currentTenantID(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if _, exists := data[product]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Product not found"})
		return
	}

	delete(data, product)
	if err := saveDir(data, arsenal); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save to database"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted", "product": product})
}

// ---------------------- API Keys Config ----------------------

// ApiKeyEntry represents one API provider's key configuration
type ApiKeyEntry struct {
	Provider string   `json:"provider"`
	Keys     []string `json:"keys"`
}

// getApiKeysConfig returns the current api-config from the Arsenal
func getApiKeysConfig(c *gin.Context) {
	arsenal, err := db.FindTenantArsenalByTypeAndFile(currentTenantID(c), "apiconfig", "api-config.yaml")
	if err != nil {
		// 如果不存在，返回空默认配置
		c.JSON(http.StatusOK, defaultApiKeyEntries())
		return
	}

	var data map[string][]string
	if err := yaml.Unmarshal([]byte(arsenal.Content), &data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse api-config"})
		return
	}

	var results []ApiKeyEntry
	for provider, keys := range data {
		results = append(results, ApiKeyEntry{Provider: provider, Keys: keys})
	}
	c.JSON(http.StatusOK, results)
}

// saveApiKeysConfig updates Server-only asset discovery credentials. Agents
// never receive this configuration or a notification that it changed.
func saveApiKeysConfig(c *gin.Context) {
	tenantID := currentTenantID(c)
	var entries []ApiKeyEntry
	if err := c.ShouldBindJSON(&entries); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 转换为 YAML 格式的 map
	data := make(map[string][]string)
	for _, entry := range entries {
		provider := strings.TrimSpace(entry.Provider)
		if provider == "" {
			continue
		}
		data[provider] = entry.Keys
	}

	out, err := yaml.Marshal(data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize config"})
		return
	}

	contentStr := string(out)
	hash := fmt.Sprintf("%x", md5.Sum(out))

	// 查找或创建 Arsenal 记录
	arsenal, findErr := db.FindTenantArsenalByTypeAndFile(tenantID, "apiconfig", "api-config.yaml")
	if findErr != nil {
		// 不存在则创建
		arsenal = &db.Arsenal{
			ID:       db.BuildTenantArsenalID(tenantID, "apiconfig", "api-config.yaml"),
			TenantID: tenantID,
			Type:     "apiconfig",
			FileName: "api-config.yaml",
			Content:  contentStr,
			Hash:     hash,
			State:    "Approved",
			Version:  1,
		}
		if err := db.DB.Create(arsenal).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create config"})
			return
		}
	} else {
		arsenal.Content = contentStr
		arsenal.Hash = hash
		arsenal.State = "Approved" // API 密钥自动审核通过
		arsenal.Version++
		if err := db.DB.Save(arsenal).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save config"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "saved", "hash": hash})
}

// defaultApiKeyEntries returns the default empty provider list
func defaultApiKeyEntries() []ApiKeyEntry {
	providers := []string{
		"bevigil", "binaryedge", "bufferover", "c99", "censys",
		"certspotter", "chaos", "chinaz", "dnsdb", "dnsrepo",
		"fofa", "fullhunt", "github", "hunter", "intelx",
		"leakix", "passivetotal", "quake", "robtex", "securitytrails",
		"shodan", "threatbook", "virustotal", "whoisxmlapi", "zoomeye",
		"zoomeyeapi",
	}
	entries := make([]ApiKeyEntry, len(providers))
	for i, p := range providers {
		entries[i] = ApiKeyEntry{Provider: p, Keys: []string{}}
	}
	return entries
}

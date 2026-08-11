package api

import (
	"crypto/md5"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

// Global variable acting as hot-reload trigger
var GlobalArsenalReloadCounter int64 = 0

func getArsenals(c *gin.Context) {
	var arsenals []db.Arsenal
	typ := db.CanonicalArsenalType(c.Param("type"))
	query := db.DB.Where("tenant_id = ? AND type IN ?", currentTenantID(c), db.ArsenalTypeAliases(typ))

	// 如果没有 ?all=1 参数，默认只下发已审核武器给 Agent
	if c.Query("all") != "1" {
		query = query.Where("state = ?", "Approved")
	}

	isLite := c.Query("lite") == "1"
	// 如果指定了 lite=1 ，则省略动辄几千上万行的巨大 Content 正文内容，只提取主要元数据
	if isLite {
		query = query.Omit("Content", "PreviousContent")
	}

	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		query = query.Where("LOWER(file_name) LIKE ? OR LOWER(state) LIKE ? OR LOWER(hash) LIKE ?", like, like, like)
	}

	if c.Query("page") != "" || c.Query("page_size") != "" || strings.TrimSpace(c.Query("q")) != "" {
		page, pageSize := parsePagination(c, 50, 200)
		var total int64
		if err := query.Model(&db.Arsenal{}).Count(&total).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := query.Order("updated_at DESC, file_name ASC, id ASC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&arsenals).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if isLite {
			clearArsenalLargeFields(arsenals)
		}
		c.JSON(http.StatusOK, pagedResponse(arsenals, total, page, pageSize, currentRuleVersion()))
		return
	}

	if err := query.Find(&arsenals).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if isLite {
		clearArsenalLargeFields(arsenals)
	}
	c.JSON(http.StatusOK, arsenals)
}

func getArsenal(c *gin.Context) {
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, typ, fn)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}
	c.JSON(http.StatusOK, arsenal)
}

func clearArsenalLargeFields(arsenals []db.Arsenal) {
	for i := range arsenals {
		arsenals[i].Content = ""
		arsenals[i].PreviousContent = ""
	}
}

func saveArsenal(c *gin.Context) {
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)

	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// EXP 包基础校验
	if typ == "exp" {
		if !strings.HasSuffix(strings.ToLower(fn), ".py") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "EXP filename must end with .py"})
			return
		}
		if err := validateExpPackage(req.Content, false); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("EXP validation failed: %v", err)})
			return
		}
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(req.Content)))

	// 查找已有记录以保存 PreviousHash/PreviousContent 和递增 Version
	var existing db.Arsenal
	var previousHash string
	var previousContent string
	var version int = 1
	approvedChanged := false
	if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).First(&existing).Error; err == nil {
		previousHash = existing.Hash
		previousContent = existing.Content // 保存当前内容用于回滚
		version = existing.Version + 1
		approvedChanged = strings.EqualFold(existing.State, "Approved")
	}

	arsenal := db.Arsenal{
		ID:              db.BuildTenantArsenalID(tenantID, typ, fn),
		TenantID:        tenantID,
		Type:            typ,
		FileName:        fn,
		Content:         req.Content,
		Hash:            hash,
		PreviousHash:    previousHash,
		PreviousContent: previousContent,
		Version:         version,
		State:           "Draft",
	}
	if typ == "poc" {
		if err := db.ValidateRuleCatalogCandidate(arsenal); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("POC governance validation failed: %v", err)})
			return
		}
	}
	if err := db.DB.Save(&arsenal).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := gin.H{"status": "saved", "hash": hash, "state": "Draft", "version": version}
	if approvedChanged && typ != "exp" {
		resp["rule_version"] = BumpRuleVersion()
	}
	c.JSON(http.StatusOK, resp)
}

func approveArsenal(c *gin.Context) {
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)
	if typ == "poc" {
		var existing db.Arsenal
		if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).First(&existing).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
			return
		}
		candidate := existing
		candidate.State = "Approved"
		if err := db.ValidateRuleCatalogCandidate(candidate); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("POC governance validation failed: %v", err)})
			return
		}
	}

	// EXP 包严格校验
	if typ == "exp" {
		var existing db.Arsenal
		if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).First(&existing).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
			return
		}
		if err := validateExpPackage(existing.Content, true); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("EXP validation failed: %v", err)})
			return
		}
	}

	if err := db.DB.Model(&db.Arsenal{}).Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).Update("state", "Approved").Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if typ == "exp" {
		c.JSON(http.StatusOK, gin.H{"status": "approved"})
		return
	}

	// 触发版本号递增
	newVersion := BumpRuleVersion()
	log.Printf("[Arsenal Hub] Rules approved by Tenant %s. Rule version bumped to %s. Global Reload Triggered!", tenantID, newVersion)

	c.JSON(http.StatusOK, gin.H{"status": "approved", "rule_version": newVersion})
}

func deleteArsenal(c *gin.Context) {
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)
	var arsenal db.Arsenal
	if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).First(&arsenal).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}
	if typ == "poc" {
		if refs := workflowReferencesForPOC(tenantID, fn); len(refs) > 0 {
			c.JSON(http.StatusConflict, gin.H{
				"error":      "POC is referenced by workflow rules",
				"references": refs,
			})
			return
		}
	}
	if err := db.DB.Delete(&db.Arsenal{}, "tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := gin.H{"status": "deleted"}
	if strings.EqualFold(arsenal.State, "Approved") && typ != "exp" {
		resp["rule_version"] = BumpRuleVersion()
	}
	c.JSON(http.StatusOK, resp)
}

func workflowReferencesForPOC(tenantID, fileName string) []gin.H {
	names := map[string]bool{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			names[value] = true
		}
	}
	add(fileName)
	add(strings.TrimSuffix(fileName, filepath.Ext(fileName)))
	var poc db.PocRule
	if err := db.DB.Where("tenant_id = ? AND source_file = ?", tenantID, fileName).First(&poc).Error; err == nil {
		add(poc.Name)
		add(poc.SourceFile)
	}
	list := make([]string, 0, len(names))
	for name := range names {
		list = append(list, name)
	}
	sort.Strings(list)
	var workflows []db.WorkflowRule
	if err := db.DB.Where("tenant_id = ? AND poc_name IN ?", tenantID, list).Order("product_name, poc_name, match_type").Find(&workflows).Error; err != nil {
		return nil
	}
	refs := make([]gin.H, 0, len(workflows))
	for _, wf := range workflows {
		refs = append(refs, gin.H{
			"product_name": wf.ProductName,
			"poc_name":     wf.PocName,
			"match_type":   wf.MatchType,
			"source_file":  wf.SourceFile,
			"state":        wf.State,
			"enabled":      wf.Enabled,
		})
	}
	return refs
}

func getArsenalManifest(c *gin.Context) {
	var arsenals []db.Arsenal
	tenantID := currentTenantID(c)
	db.DB.Select("type, file_name, hash, state, updated_at").
		Where("tenant_id = ? AND state = ? AND type IN ?", tenantID, "Approved", agentSyncArsenalTypes()).
		Find(&arsenals)

	type ManifestItem struct {
		Type      string `json:"type"`
		FileName  string `json:"file_name"`
		Hash      string `json:"hash"`
		UpdatedAt string `json:"updated_at"`
	}

	ruleVersion := currentRuleVersionValue()

	items := make([]ManifestItem, 0, len(arsenals))
	for _, a := range arsenals {
		items = append(items, ManifestItem{
			Type:      db.CanonicalArsenalType(a.Type),
			FileName:  a.FileName,
			Hash:      a.Hash,
			UpdatedAt: a.UpdatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"rule_version": ruleVersion,
		"items":        items,
	})
}

// GetCurrentRuleVersion 获取当前规则版本号
func GetCurrentRuleVersion() string {
	var cfg db.SystemConfig
	if db.DB.Where("key = ?", "rule_version").First(&cfg).Error == nil {
		return cfg.Value
	}
	return ""
}

// BumpRuleVersion 生成并保存新的规则版本号
func BumpRuleVersion() string {
	version := fmt.Sprintf("v%s.%03d", time.Now().Format("2006.01.02"), time.Now().UnixMilli()%1000)
	cfg := db.SystemConfig{
		Key:       "rule_version",
		Value:     version,
		UpdatedAt: time.Now(),
	}
	db.DB.Save(&cfg)
	return version
}

func rollbackArsenal(c *gin.Context) {
	typ := db.CanonicalArsenalType(c.Param("type"))
	fn := c.Param("filename")
	tenantID := currentTenantID(c)

	var arsenal db.Arsenal
	if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, typ, fn).First(&arsenal).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}

	if arsenal.PreviousHash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No previous version available for rollback"})
		return
	}

	// 交换当前版本和上一版本（含 Content 内容回滚）
	if err := db.DB.Model(&arsenal).Updates(map[string]interface{}{
		"content":          arsenal.PreviousContent,
		"previous_content": arsenal.Content,
		"hash":             arsenal.PreviousHash,
		"previous_hash":    arsenal.Hash,
		"state":            "Draft", // 回滚后重新审批
		"version":          arsenal.Version + 1,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 触发全网 Agent 重新拉取
	newVersion := BumpRuleVersion()
	log.Printf("[Arsenal Hub] Rule %s/%s rolled back. Rule version: %s", typ, fn, newVersion)

	c.JSON(http.StatusOK, gin.H{"status": "rolled_back", "rule_version": newVersion})
}

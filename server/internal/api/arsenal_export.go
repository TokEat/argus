package api

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// 历史说明：此前包内 Poc.Name 带 uniqueIndex，重名规则只能保留一条，
// 且选择顺序不确定，导致风险验证计划引用未进包的模板文件。现在唯一性
// 落在 FileName 上（poc_rules 以 tenant+source_file 唯一），全部启用规
// 原样下发，不再需要任何代表选择逻辑。

// ====================================================================
// Agent-side arsenal.db SQLite schema (mirrors scanner/internal/arsenal/models.go)
// 在 Server 端重新定义这些结构体，避免跨模块依赖。
// 表名 / 字段必须与 scanner/internal/arsenal/models.go 完全一致。
// ====================================================================

type agentFingerprint struct {
	ID          uint      `gorm:"primaryKey;autoIncrement"`
	ProductName string    `gorm:"index;not null"`
	RuleExpr    string    `gorm:"not null"`
	Category    string    `gorm:"index;default:'web'"`
	Tags        string    ``
	Enabled     bool      `gorm:"default:true"`
	Source      string    `gorm:"default:'server'"`
	CreatedAt   time.Time ``
	UpdatedAt   time.Time ``
}

func (agentFingerprint) TableName() string { return "fingerprints" }

type agentPoc struct {
	ID uint `gorm:"primaryKey;autoIncrement"`
	// Name 只是模板内部 ID，不同模板可能重名（历史数据存在 4 组）；
	// 唯一性必须落在 FileName 上，否则按 Name 去重会随机丢弃其中一个
	// 模板文件，导致风险验证计划引用 Agent 上不存在的 POC。
	Name           string    `gorm:"index;not null"`
	FileName       string    `gorm:"uniqueIndex;not null"`
	Content        string    ``
	ContentHash    string    ``
	Severity       string    `gorm:"index;default:'info'"`
	ExecutionClass string    `gorm:"index;default:'detection'"`
	RiskLevel      string    `gorm:"index;default:'unknown'"`
	Tags           string    ``
	Author         string    ``
	Description    string    ``
	Enabled        bool      `gorm:"default:true"`
	Source         string    `gorm:"default:'server'"`
	CreatedAt      time.Time ``
	UpdatedAt      time.Time ``
}

func (agentPoc) TableName() string { return "pocs" }

type agentActiveFingerprint struct {
	ID           uint   `gorm:"primaryKey;autoIncrement"`
	Name         string `gorm:"index;not null"`
	FileName     string `gorm:"uniqueIndex;not null"`
	ProductName  string `gorm:"index;not null"`
	Content      string
	ContentHash  string
	AutoEligible bool   `gorm:"index"`
	Enabled      bool   `gorm:"default:true"`
	Source       string `gorm:"default:'server'"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (agentActiveFingerprint) TableName() string { return "active_fingerprints" }

type agentPocAsset struct {
	ID           uint      `gorm:"primaryKey;autoIncrement"`
	RelativePath string    `gorm:"uniqueIndex;not null"`
	Content      string    ``
	ContentHash  string    ``
	Enabled      bool      `gorm:"default:true"`
	Source       string    `gorm:"default:'server'"`
	CreatedAt    time.Time ``
	UpdatedAt    time.Time ``
}

func (agentPocAsset) TableName() string { return "poc_assets" }

type agentConfigAsset struct {
	ID           uint      `gorm:"primaryKey;autoIncrement"`
	RelativePath string    `gorm:"uniqueIndex;not null"`
	Content      string    ``
	ContentHash  string    ``
	Enabled      bool      `gorm:"default:true"`
	Source       string    `gorm:"default:'server'"`
	CreatedAt    time.Time ``
	UpdatedAt    time.Time ``
}

func (agentConfigAsset) TableName() string { return "config_assets" }

type agentWorkflow struct {
	ID          uint      `gorm:"primaryKey;autoIncrement"`
	ProductName string    `gorm:"index;not null"`
	PocName     string    `gorm:"index;not null"`
	MatchType   string    `gorm:"not null"`
	RiskLevel   string    `gorm:"index;default:'unknown'"`
	Enabled     bool      `gorm:"default:true"`
	CreatedAt   time.Time ``
	UpdatedAt   time.Time ``
}

func (agentWorkflow) TableName() string { return "workflows" }

type agentDirProbe struct {
	ID          uint      `gorm:"primaryKey;autoIncrement"`
	Path        string    `gorm:"index;not null"`
	ProductName string    `gorm:"index;not null"`
	Enabled     bool      `gorm:"default:true"`
	CreatedAt   time.Time ``
	UpdatedAt   time.Time ``
}

func (agentDirProbe) TableName() string { return "dir_probes" }

func agentSyncArsenalTypes() []string {
	types := append([]string{}, db.ArsenalTypeAliases("finger")...)
	types = append(types, db.ArsenalTypeAliases("workflow")...)
	types = append(types, db.ArsenalTypeAliases("dir")...)
	types = append(types, db.ArsenalTypeAliases("poc")...)
	types = append(types, db.ArsenalTypeAliases("active_fingerprint")...)
	types = append(types, db.ArsenalTypeAliases("poc_asset")...)
	types = append(types, db.ArsenalTypeAliases("config_asset")...)
	return types
}

// ====================================================================
// 构建 SQLite DB 文件
// ====================================================================

// buildArsenalSQLiteDB 从 PostgreSQL 的结构化规则表中读取已启用的规则，
// 构建一个与 Agent 端 arsenal.db 完全兼容的 SQLite 文件。
// 返回临时文件路径、文件内容的 MD5 Hash 和小写 SHA-256 Hash。调用者负责在使用后删除临时文件。
func buildArsenalSQLiteDB(tenantID string) (filePath string, md5Hash string, sha256Hash string, err error) {
	tmpFile, err := os.CreateTemp("", "arsenal-export-*.db")
	if err != nil {
		return "", "", "", fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	// 打开 SQLite
	sdb, err := gorm.Open(sqlite.Open(tmpPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		os.Remove(tmpPath)
		return "", "", "", fmt.Errorf("打开临时 SQLite 失败: %w", err)
	}

	// 创建表结构（与 Agent 端 arsenal 包一致）
	if err := sdb.AutoMigrate(
		&agentFingerprint{},
		&agentPoc{},
		&agentActiveFingerprint{},
		&agentPocAsset{},
		&agentConfigAsset{},
		&agentWorkflow{},
		&agentDirProbe{},
	); err != nil {
		os.Remove(tmpPath)
		return "", "", "", fmt.Errorf("SQLite AutoMigrate 失败: %w", err)
	}

	now := time.Now()

	// --- 导入指纹 ---
	var fpRules []db.FingerprintRule
	db.DB.Where("tenant_id = ? AND enabled = ?", tenantID, true).Find(&fpRules)
	if len(fpRules) > 0 {
		batch := make([]agentFingerprint, 0, len(fpRules))
		for _, r := range fpRules {
			batch = append(batch, agentFingerprint{
				ProductName: r.ProductName,
				RuleExpr:    r.RuleExpr,
				Category:    r.Category,
				Tags:        "",
				Enabled:     true,
				Source:      "server",
				CreatedAt:   now,
				UpdatedAt:   now,
			})
		}
		sdb.CreateInBatches(batch, 500)
	}

	// --- 导入 POC（需要从 Arsenal 表获取完整 Content）---
	var pocRules []db.PocRule
	db.DB.Where("tenant_id = ? AND enabled = ?", tenantID, true).Find(&pocRules)
	if len(pocRules) > 0 {
		// 收集所有 POC 的 ArtifactID，批量查询 Arsenal 表获取 Content
		artifactIDs := make([]string, 0, len(pocRules))
		for _, r := range pocRules {
			if r.ArtifactID != "" {
				artifactIDs = append(artifactIDs, r.ArtifactID)
			}
		}

		contentMap := make(map[string]string) // artifactID → Content
		if len(artifactIDs) > 0 {
			var arsenals []db.Arsenal
			db.DB.Select("id, content").Where("tenant_id = ? AND id IN ?", tenantID, artifactIDs).Find(&arsenals)
			for _, a := range arsenals {
				contentMap[a.ID] = a.Content
			}
		}

		// 全量写入：FileName 在包内唯一（poc_rules 以 tenant+source_file 唯一），
		// 重名模板各自携带不同文件，必须全部下发；按 Name 去重会随机丢失
		// 其中一个文件，导致风险验证计划引用 Agent 上不存在的 POC。
		batch := make([]agentPoc, 0, len(pocRules))
		for _, r := range pocRules {
			content := contentMap[r.ArtifactID]
			batch = append(batch, agentPoc{
				Name:           r.Name,
				FileName:       r.SourceFile,
				Content:        content,
				ContentHash:    r.ContentHash,
				Severity:       r.Severity,
				ExecutionClass: r.ExecutionClass,
				RiskLevel:      r.RiskLevel,
				Tags:           r.Tags,
				Author:         r.Author,
				Description:    r.Description,
				Enabled:        true,
				Source:         "server",
				CreatedAt:      now,
				UpdatedAt:      now,
			})
		}
		if err := sdb.CreateInBatches(batch, 500).Error; err != nil {
			log.Printf("[ArsenalExport] ⚠️ POC 批量写入 SQLite 失败: %v (count=%d)", err, len(batch))
		}
	}

	var activeRules []db.ActiveFingerprintRule
	if queryErr := db.DB.Where("tenant_id = ? AND enabled = ? AND auto_eligible = ? AND LOWER(state) = ?", tenantID, true, true, "approved").Order("source_file").Find(&activeRules).Error; queryErr != nil {
		closeSQLite(sdb)
		os.Remove(tmpPath)
		return "", "", "", fmt.Errorf("读取主动行为指纹失败: %w", queryErr)
	}
	if len(activeRules) > 0 {
		artifactIDs := make([]string, 0, len(activeRules))
		for _, rule := range activeRules {
			artifactIDs = append(artifactIDs, rule.ArtifactID)
		}
		var arsenals []db.Arsenal
		if queryErr := db.DB.Where("tenant_id = ? AND id IN ?", tenantID, artifactIDs).Find(&arsenals).Error; queryErr != nil {
			closeSQLite(sdb)
			os.Remove(tmpPath)
			return "", "", "", fmt.Errorf("读取主动行为指纹原文失败: %w", queryErr)
		}
		contents := make(map[string]db.Arsenal, len(arsenals))
		for _, arsenal := range arsenals {
			contents[arsenal.ID] = arsenal
		}
		batch := make([]agentActiveFingerprint, 0, len(activeRules))
		for _, rule := range activeRules {
			arsenal, exists := contents[rule.ArtifactID]
			actualHash := fmt.Sprintf("%x", md5.Sum([]byte(arsenal.Content)))
			if !exists || !strings.EqualFold(strings.TrimSpace(arsenal.State), "approved") || arsenal.Version != rule.Version ||
				!strings.EqualFold(strings.TrimSpace(arsenal.Hash), strings.TrimSpace(rule.ContentHash)) ||
				!strings.EqualFold(strings.TrimSpace(arsenal.Hash), actualHash) {
				closeSQLite(sdb)
				os.Remove(tmpPath)
				return "", "", "", fmt.Errorf("主动行为指纹 %s 原文与已发布索引不一致", rule.SourceFile)
			}
			batch = append(batch, agentActiveFingerprint{Name: rule.Name, FileName: rule.SourceFile, ProductName: rule.ProductName,
				Content: arsenal.Content, ContentHash: rule.ContentHash, AutoEligible: true, Enabled: true,
				Source: "server", CreatedAt: now, UpdatedAt: now})
		}
		if err := sdb.CreateInBatches(batch, 500).Error; err != nil {
			closeSQLite(sdb)
			os.Remove(tmpPath)
			return "", "", "", fmt.Errorf("主动行为指纹写入 SQLite 失败: %w", err)
		}
	}

	// --- 导入 POC 辅助资产（helpers payloads/wordlists 等，保留相对路径）---
	var pocAssets []db.Arsenal
	db.DB.
		Where("tenant_id = ? AND state = ? AND type IN ?", tenantID, "Approved", db.ArsenalTypeAliases("poc_asset")).
		Order("file_name").
		Find(&pocAssets)
	if len(pocAssets) > 0 {
		batch := make([]agentPocAsset, 0, len(pocAssets))
		for _, a := range pocAssets {
			if a.FileName == "" || a.Content == "" {
				continue
			}
			hash := a.Hash
			if hash == "" {
				hash = fmt.Sprintf("%x", md5.Sum([]byte(a.Content)))
			}
			batch = append(batch, agentPocAsset{
				RelativePath: a.FileName,
				Content:      a.Content,
				ContentHash:  hash,
				Enabled:      true,
				Source:       "server",
				CreatedAt:    now,
				UpdatedAt:    now,
			})
		}
		if len(batch) > 0 {
			if err := sdb.CreateInBatches(batch, 500).Error; err != nil {
				log.Printf("[ArsenalExport] ⚠️ POC 辅助资产写入 SQLite 失败: %v (count=%d)", err, len(batch))
			}
		}
	}

	// --- 导入运行时配置资产（GoPoc 字典、子域名字典等，不包含凭据配置）---
	var configAssets []db.Arsenal
	db.DB.
		Where("tenant_id = ? AND state = ? AND type IN ?", tenantID, "Approved", db.ArsenalTypeAliases("config_asset")).
		Order("file_name").
		Find(&configAssets)
	if len(configAssets) > 0 {
		batch := make([]agentConfigAsset, 0, len(configAssets))
		for _, a := range configAssets {
			if a.FileName == "" || a.Content == "" {
				continue
			}
			hash := a.Hash
			if hash == "" {
				hash = fmt.Sprintf("%x", md5.Sum([]byte(a.Content)))
			}
			batch = append(batch, agentConfigAsset{
				RelativePath: a.FileName,
				Content:      a.Content,
				ContentHash:  hash,
				Enabled:      true,
				Source:       "server",
				CreatedAt:    now,
				UpdatedAt:    now,
			})
		}
		if len(batch) > 0 {
			if err := sdb.CreateInBatches(batch, 500).Error; err != nil {
				log.Printf("[ArsenalExport] ⚠️ 配置资产写入 SQLite 失败: %v (count=%d)", err, len(batch))
			}
		}
	}

	// --- 导入 Workflow ---
	// 附加每个 PocName 的风险等级（重名取最严格），供 Agent 在本地
	// workflow 匹配时执行高危预授权门，无需服务端显式映射表。
	riskByPocName := make(map[string]string, len(pocRules))
	for _, r := range pocRules {
		existing, exists := riskByPocName[r.Name]
		if !exists || pocRiskRank(r.RiskLevel) > pocRiskRank(existing) {
			existing = r.RiskLevel
		}
		riskByPocName[r.Name] = existing
	}
	var wfRules []db.WorkflowRule
	db.DB.Where("tenant_id = ? AND enabled = ?", tenantID, true).Find(&wfRules)
	if len(wfRules) > 0 {
		batch := make([]agentWorkflow, 0, len(wfRules))
		for _, r := range wfRules {
			batch = append(batch, agentWorkflow{
				ProductName: r.ProductName,
				PocName:     r.PocName,
				MatchType:   r.MatchType,
				RiskLevel:   riskByPocName[r.PocName],
				Enabled:     true,
				CreatedAt:   now,
				UpdatedAt:   now,
			})
		}
		sdb.CreateInBatches(batch, 500)
	}

	// --- 导入 DirProbe ---
	var dirRules []db.DirRule
	db.DB.Where("tenant_id = ? AND enabled = ?", tenantID, true).Find(&dirRules)
	if len(dirRules) > 0 {
		batch := make([]agentDirProbe, 0, len(dirRules))
		for _, r := range dirRules {
			batch = append(batch, agentDirProbe{
				Path:        r.Path,
				ProductName: r.ProductName,
				Enabled:     true,
				CreatedAt:   now,
				UpdatedAt:   now,
			})
		}
		sdb.CreateInBatches(batch, 500)
	}

	// 关闭 SQLite 连接
	sqlDB, _ := sdb.DB()
	if sqlDB != nil {
		sqlDB.Close()
	}

	// 计算文件 Hash
	fileData, err := os.ReadFile(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return "", "", "", fmt.Errorf("读取生成的 DB 文件失败: %w", err)
	}
	fileMD5Hash := fmt.Sprintf("%x", md5.Sum(fileData))
	fileSHA256Hash := fmt.Sprintf("%x", sha256.Sum256(fileData))

	log.Printf("[ArsenalExport] SQLite DB 构建完成: fingerprints=%d, active_fingerprints=%d, pocs=%d, poc_assets=%d, config_assets=%d, workflows=%d, dirs=%d, size=%d bytes, md5=%s, sha256=%s",
		len(fpRules), len(activeRules), len(pocRules), len(pocAssets), len(configAssets), len(wfRules), len(dirRules), len(fileData), fileMD5Hash[:8], fileSHA256Hash[:8])

	return tmpPath, fileMD5Hash, fileSHA256Hash, nil
}

// buildArsenalSeedSQLiteDB 从 PostgreSQL 的 arsenals 原始表导出安装/迁移用 seed DB。
// 文件结构与 server/scripts/build_seed_db.go 生成的 deploy/arsenal_seed.db 一致，
// 可直接通过 argus-server --seed-from-db 导入。
func buildArsenalSeedSQLiteDB(tenantID string) (filePath string, hash string, count int, err error) {
	tmpFile, err := os.CreateTemp("", "arsenal-seed-export-*.db")
	if err != nil {
		return "", "", 0, fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	sdb, err := gorm.Open(sqlite.Open(tmpPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		os.Remove(tmpPath)
		return "", "", 0, fmt.Errorf("打开临时 SQLite 失败: %w", err)
	}

	if err := sdb.AutoMigrate(&db.Arsenal{}); err != nil {
		closeSQLite(sdb)
		os.Remove(tmpPath)
		return "", "", 0, fmt.Errorf("SQLite AutoMigrate 失败: %w", err)
	}

	var arsenals []db.Arsenal
	exportTypes := agentSyncArsenalTypes()
	if err := db.DB.
		Where("tenant_id = ? AND type IN ?", tenantID, exportTypes).
		Order("type, file_name").
		Find(&arsenals).Error; err != nil {
		closeSQLite(sdb)
		os.Remove(tmpPath)
		return "", "", 0, fmt.Errorf("读取弹药库失败: %w", err)
	}

	for i := range arsenals {
		arsenals[i].Type = db.CanonicalArsenalType(arsenals[i].Type)
		if arsenals[i].ID == "" {
			arsenals[i].ID = db.BuildTenantArsenalID(arsenals[i].TenantID, arsenals[i].Type, arsenals[i].FileName)
		}
	}

	if len(arsenals) > 0 {
		if err := sdb.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"tenant_id", "type", "file_name", "content", "hash", "previous_hash", "previous_content", "version", "state", "created_at", "updated_at"}),
		}).CreateInBatches(arsenals, 200).Error; err != nil {
			closeSQLite(sdb)
			os.Remove(tmpPath)
			return "", "", 0, fmt.Errorf("写入 seed DB 失败: %w", err)
		}
	}

	closeSQLite(sdb)

	fileData, err := os.ReadFile(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return "", "", 0, fmt.Errorf("读取生成的 DB 文件失败: %w", err)
	}
	fileHash := fmt.Sprintf("%x", md5.Sum(fileData))

	log.Printf("[ArsenalSeedExport] SQLite seed DB 构建完成: count=%d, size=%d bytes, hash=%s",
		len(arsenals), len(fileData), fileHash[:8])

	return tmpPath, fileHash, len(arsenals), nil
}

func closeSQLite(database *gorm.DB) {
	sqlDB, _ := database.DB()
	if sqlDB != nil {
		sqlDB.Close()
	}
}

// ====================================================================
// HTTP 处理函数
// ====================================================================

// getArsenalDB 构建并下载 Agent 端可直接使用的 arsenal.db 文件。
// GET /api/v1/arsenals/db
func getArsenalDB(c *gin.Context) {
	tenantID := currentTenantID(c)
	tmpPath, md5Hash, sha256Hash, err := buildArsenalSQLiteDB(tenantID)
	if err != nil {
		log.Printf("[ArsenalExport] 构建失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer os.Remove(tmpPath)

	c.Header("X-Arsenal-Hash", md5Hash)
	c.Header("X-Arsenal-SHA256", sha256Hash)
	c.Header("Content-Disposition", "attachment; filename=arsenal.db")
	c.File(tmpPath)
}

// exportArsenalSeedDB 下载安装/迁移用的 arsenal_seed.db。
// GET /api/v1/arsenals/seed-db
func exportArsenalSeedDB(c *gin.Context) {
	tenantID := currentTenantID(c)
	tmpPath, hash, count, err := buildArsenalSeedSQLiteDB(tenantID)
	if err != nil {
		log.Printf("[ArsenalSeedExport] 构建失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer os.Remove(tmpPath)

	filename := fmt.Sprintf("arsenal_seed_%s_%s.db", tenantID, time.Now().Format("20060102_150405"))
	c.Header("X-Arsenal-Seed-Hash", hash)
	c.Header("X-Arsenal-Seed-Count", fmt.Sprintf("%d", count))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.File(tmpPath)
}

// getArsenalDBHash 返回当前 arsenal.db 的 Hash 值，供 Agent 做增量对比。
// GET /api/v1/arsenals/db/hash
func getArsenalDBHash(c *gin.Context) {
	// 使用与 manifest 相同的聚合 Hash 逻辑（基于 Arsenal 表内容），
	// 这样无需每次都构建完整 SQLite 文件。
	var arsenals []db.Arsenal
	tenantID := currentTenantID(c)
	db.DB.Select("tenant_id, type, file_name, hash, state, version").
		Where("tenant_id = ? AND state = ? AND type IN ?", tenantID, "Approved", agentSyncArsenalTypes()).
		Order("tenant_id, type, file_name").
		Find(&arsenals)

	aggregateHash := buildExportAggregateHash(arsenals)

	c.JSON(http.StatusOK, gin.H{
		"hash":          aggregateHash,
		"rule_version":  currentRuleVersionValue(),
		"arsenal_count": len(arsenals),
	})
}

// pocRiskRank 将风险等级映射为严重度序（用于重名模板取最严格等级）。
func pocRiskRank(riskLevel string) int {
	switch strings.ToLower(strings.TrimSpace(riskLevel)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low", "info":
		return 1
	default:
		return 0
	}
}

// buildExportAggregateHash 计算 Arsenal 表当前 Approved 记录的聚合 hash。
func buildExportAggregateHash(arsenals []db.Arsenal) string {
	if len(arsenals) == 0 {
		return ""
	}

	h := md5.New()
	// 导出器组装逻辑版本盐：包内容生成方式变化（如去重策略、索引调整）时
	// 必须递增，否则 arsenals 表未变会导致聚合 hash 不变，Agent 永远判定
	// "已是最新"而拿不到修复后的完整规则包。
	fmt.Fprintln(h, "argus-arsenal-export/v2")
	for _, a := range arsenals {
		fmt.Fprintf(h, "%s|%s|%s|%s|%s|%d\n",
			a.TenantID,
			db.CanonicalArsenalType(a.Type),
			a.FileName,
			a.Hash,
			a.State,
			a.Version,
		)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// getArsenalDBStats 返回 DB 导出的统计信息（调试用）。
func getArsenalDBStats(c *gin.Context) {
	tenantID := currentTenantID(c)
	var fpCount, pocCount, pocAssetCount, configAssetCount, wfCount, dirCount int64
	db.DB.Model(&db.FingerprintRule{}).Where("tenant_id = ? AND enabled = ?", tenantID, true).Count(&fpCount)
	db.DB.Model(&db.PocRule{}).Where("tenant_id = ? AND enabled = ?", tenantID, true).Count(&pocCount)
	db.DB.Model(&db.Arsenal{}).Where("tenant_id = ? AND state = ? AND type IN ?", tenantID, "Approved", db.ArsenalTypeAliases("poc_asset")).Count(&pocAssetCount)
	db.DB.Model(&db.Arsenal{}).Where("tenant_id = ? AND state = ? AND type IN ?", tenantID, "Approved", db.ArsenalTypeAliases("config_asset")).Count(&configAssetCount)
	db.DB.Model(&db.WorkflowRule{}).Where("tenant_id = ? AND enabled = ?", tenantID, true).Count(&wfCount)
	db.DB.Model(&db.DirRule{}).Where("tenant_id = ? AND enabled = ?", tenantID, true).Count(&dirCount)

	dbSize := int64(0)
	dbPath := filepath.Join("data", "arsenal.db")
	if info, err := os.Stat(dbPath); err == nil {
		dbSize = info.Size()
	}

	c.JSON(http.StatusOK, gin.H{
		"fingerprints":  fpCount,
		"pocs":          pocCount,
		"poc_assets":    pocAssetCount,
		"config_assets": configAssetCount,
		"workflows":     wfCount,
		"dir_probes":    dirCount,
		"local_db_size": dbSize,
	})
}

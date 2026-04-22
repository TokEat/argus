package api

import (
	"crypto/md5"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/user/dddd-server/internal/db"

	"github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

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
	ID          uint      `gorm:"primaryKey;autoIncrement"`
	Name        string    `gorm:"uniqueIndex;not null"`
	FileName    string    `gorm:"index;not null"`
	Content     string    ``
	ContentHash string    ``
	Severity    string    `gorm:"index;default:'info'"`
	Tags        string    ``
	Author      string    ``
	Description string    ``
	Enabled     bool      `gorm:"default:true"`
	Source      string    `gorm:"default:'server'"`
	CreatedAt   time.Time ``
	UpdatedAt   time.Time ``
}

func (agentPoc) TableName() string { return "pocs" }

type agentWorkflow struct {
	ID          uint      `gorm:"primaryKey;autoIncrement"`
	ProductName string    `gorm:"index;not null"`
	PocName     string    `gorm:"index;not null"`
	MatchType   string    `gorm:"not null"`
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

// ====================================================================
// 构建 SQLite DB 文件
// ====================================================================

// buildArsenalSQLiteDB 从 PostgreSQL 的结构化规则表中读取已启用的规则，
// 构建一个与 Agent 端 arsenal.db 完全兼容的 SQLite 文件。
// 返回临时文件路径和文件内容的 MD5 Hash。调用者负责在使用后删除临时文件。
func buildArsenalSQLiteDB() (filePath string, hash string, err error) {
	tmpFile, err := os.CreateTemp("", "arsenal-export-*.db")
	if err != nil {
		return "", "", fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	// 打开 SQLite
	sdb, err := gorm.Open(sqlite.Open(tmpPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		os.Remove(tmpPath)
		return "", "", fmt.Errorf("打开临时 SQLite 失败: %w", err)
	}

	// 创建表结构（与 Agent 端 arsenal 包一致）
	if err := sdb.AutoMigrate(
		&agentFingerprint{},
		&agentPoc{},
		&agentWorkflow{},
		&agentDirProbe{},
	); err != nil {
		os.Remove(tmpPath)
		return "", "", fmt.Errorf("SQLite AutoMigrate 失败: %w", err)
	}

	now := time.Now()

	// --- 导入指纹 ---
	var fpRules []db.FingerprintRule
	db.DB.Where("enabled = ?", true).Find(&fpRules)
	if len(fpRules) > 0 {
		batch := make([]agentFingerprint, 0, len(fpRules))
		for _, r := range fpRules {
			batch = append(batch, agentFingerprint{
				ProductName: r.ProductName,
				RuleExpr:    r.RuleExpr,
				Category:    r.Category,
				Tags:        "",
				Enabled:     true,
				Source:       "server",
				CreatedAt:   now,
				UpdatedAt:   now,
			})
		}
		sdb.CreateInBatches(batch, 500)
	}

	// --- 导入 POC（需要从 Arsenal 表获取完整 Content）---
	var pocRules []db.PocRule
	db.DB.Where("enabled = ?", true).Find(&pocRules)
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
			db.DB.Select("id, content").Where("id IN ?", artifactIDs).Find(&arsenals)
			for _, a := range arsenals {
				contentMap[a.ID] = a.Content
			}
		}

		batch := make([]agentPoc, 0, len(pocRules))
		for _, r := range pocRules {
			content := contentMap[r.ArtifactID]
			batch = append(batch, agentPoc{
				Name:        r.Name,
				FileName:    r.SourceFile,
				Content:     content,
				ContentHash: r.ContentHash,
				Severity:    r.Severity,
				Tags:        r.Tags,
				Author:      r.Author,
				Description: r.Description,
				Enabled:     true,
				Source:       "server",
				CreatedAt:   now,
				UpdatedAt:   now,
			})
		}
		sdb.CreateInBatches(batch, 500)
	}

	// --- 导入 Workflow ---
	var wfRules []db.WorkflowRule
	db.DB.Where("enabled = ?", true).Find(&wfRules)
	if len(wfRules) > 0 {
		batch := make([]agentWorkflow, 0, len(wfRules))
		for _, r := range wfRules {
			batch = append(batch, agentWorkflow{
				ProductName: r.ProductName,
				PocName:     r.PocName,
				MatchType:   r.MatchType,
				Enabled:     true,
				CreatedAt:   now,
				UpdatedAt:   now,
			})
		}
		sdb.CreateInBatches(batch, 500)
	}

	// --- 导入 DirProbe ---
	var dirRules []db.DirRule
	db.DB.Where("enabled = ?", true).Find(&dirRules)
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
		return "", "", fmt.Errorf("读取生成的 DB 文件失败: %w", err)
	}
	fileHash := fmt.Sprintf("%x", md5.Sum(fileData))

	log.Printf("[ArsenalExport] SQLite DB 构建完成: fingerprints=%d, pocs=%d, workflows=%d, dirs=%d, size=%d bytes, hash=%s",
		len(fpRules), len(pocRules), len(wfRules), len(dirRules), len(fileData), fileHash[:8])

	return tmpPath, fileHash, nil
}

// ====================================================================
// HTTP 处理函数
// ====================================================================

// getArsenalDB 构建并下载 Agent 端可直接使用的 arsenal.db 文件。
// GET /api/v1/arsenals/db
func getArsenalDB(c *gin.Context) {
	tmpPath, hash, err := buildArsenalSQLiteDB()
	if err != nil {
		log.Printf("[ArsenalExport] 构建失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer os.Remove(tmpPath)

	c.Header("X-Arsenal-Hash", hash)
	c.Header("Content-Disposition", "attachment; filename=arsenal.db")
	c.File(tmpPath)
}

// getArsenalDBHash 返回当前 arsenal.db 的 Hash 值，供 Agent 做增量对比。
// GET /api/v1/arsenals/db/hash
func getArsenalDBHash(c *gin.Context) {
	// 使用与 manifest 相同的聚合 Hash 逻辑（基于 Arsenal 表内容），
	// 这样无需每次都构建完整 SQLite 文件。
	var arsenals []db.Arsenal
	db.DB.Select("tenant_id, type, file_name, hash, state, version").
		Where("state = ?", "Approved").
		Order("tenant_id, type, file_name").
		Find(&arsenals)

	aggregateHash := buildExportAggregateHash(arsenals)

	// 同时返回 rule_version 供日志展示
	var cfg db.SystemConfig
	ruleVersion := "unknown"
	if db.DB.Where("key = ?", "rule_version").First(&cfg).Error == nil {
		ruleVersion = cfg.Value
	}

	c.JSON(http.StatusOK, gin.H{
		"hash":         aggregateHash,
		"rule_version": ruleVersion,
		"arsenal_count": len(arsenals),
	})
}

// buildExportAggregateHash 计算 Arsenal 表当前 Approved 记录的聚合 hash。
func buildExportAggregateHash(arsenals []db.Arsenal) string {
	if len(arsenals) == 0 {
		return ""
	}

	h := md5.New()
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
	var fpCount, pocCount, wfCount, dirCount int64
	db.DB.Model(&db.FingerprintRule{}).Where("enabled = ?", true).Count(&fpCount)
	db.DB.Model(&db.PocRule{}).Where("enabled = ?", true).Count(&pocCount)
	db.DB.Model(&db.WorkflowRule{}).Where("enabled = ?", true).Count(&wfCount)
	db.DB.Model(&db.DirRule{}).Where("enabled = ?", true).Count(&dirCount)

	dbSize := int64(0)
	dbPath := filepath.Join("data", "arsenal.db")
	if info, err := os.Stat(dbPath); err == nil {
		dbSize = info.Size()
	}

	c.JSON(http.StatusOK, gin.H{
		"fingerprints": fpCount,
		"pocs":         pocCount,
		"workflows":    wfCount,
		"dir_probes":   dirCount,
		"local_db_size": dbSize,
	})
}

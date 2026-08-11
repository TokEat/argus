package arsenal

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB 弹药库数据库连接（包级别，由 OpenDB 初始化）。
var DB *gorm.DB

// DefaultDBPath 默认本地 SQLite 路径。
const DefaultDBPath = "data/arsenal.db"

var configuredDefaultDBPath = DefaultDBPath

// SetDefaultDBPath changes the process-local database used by CLI management
// subcommands when they do not provide an explicit path. Agent and Server
// package materialization always passes an explicit path and is unaffected.
func SetDefaultDBPath(path string) {
	if path = strings.TrimSpace(path); path != "" {
		configuredDefaultDBPath = path
	}
}

// ConfiguredDefaultDBPath returns the process-local CLI database path.
func ConfiguredDefaultDBPath() string {
	return configuredDefaultDBPath
}

// OpenDB 打开弹药库数据库并自动迁移表结构。
// 传空字符串使用默认路径。
func OpenDB(dsn string) error {
	if strings.TrimSpace(dsn) == "" {
		dsn = configuredDefaultDBPath
	}

	dir := filepath.Dir(dsn)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建数据目录失败: %w", err)
		}
	}

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("打开数据库失败: %w", err)
	}

	if err := db.AutoMigrate(&Fingerprint{}, &Poc{}, &PocAsset{}, &ConfigAsset{}, &Workflow{}, &DirProbe{}); err != nil {
		return fmt.Errorf("自动迁移表结构失败: %w", err)
	}

	closeCurrentDB()
	DB = db
	return nil
}

// OpenExistingDB opens an existing rule package without migrating or otherwise
// mutating it. Package validation and materialization must never repair an
// untrusted or incompatible replacement in place.
func OpenExistingDB(dsn string) error {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return fmt.Errorf("arsenal db path is required")
	}
	absPath, err := filepath.Abs(filepath.Clean(dsn))
	if err != nil {
		return fmt.Errorf("normalize arsenal db path: %w", err)
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return fmt.Errorf("inspect arsenal db: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("arsenal db must be a regular non-symlink file")
	}

	uriPath := filepath.ToSlash(absPath)
	if runtime.GOOS == "windows" && !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := &url.URL{Scheme: "file", Path: uriPath}
	query := uri.Query()
	query.Set("mode", "ro")
	uri.RawQuery = query.Encode()
	dsn = uri.String()
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("open existing arsenal db: %w", err)
	}
	if err := db.Exec("PRAGMA query_only = ON").Error; err != nil {
		if sqlDB, sqlErr := db.DB(); sqlErr == nil {
			_ = sqlDB.Close()
		}
		return fmt.Errorf("enable read-only arsenal db: %w", err)
	}

	closeCurrentDB()
	DB = db
	return nil
}

// CloseDB releases the current package database. Materialized scanners only
// use exported rule files, so they must not keep arsenal.db locked on Windows.
func CloseDB() error {
	if DB == nil {
		return nil
	}
	db := DB
	DB = nil
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func closeCurrentDB() {
	_ = CloseDB()
}

// MustOpenDB 打开数据库，失败直接退出。
func MustOpenDB(dsn string) {
	if err := OpenDB(dsn); err != nil {
		log.Fatalf("Arsenal DB 初始化失败: %v", err)
	}
}

// IsDBReady 检查数据库是否已初始化且有数据。
func IsDBReady() bool {
	if DB == nil {
		return false
	}
	var count int64
	DB.Model(&Fingerprint{}).Count(&count)
	return count > 0
}

// ---------- Fingerprint CRUD ----------

// AddFingerprint 添加一条指纹规则（去重：ProductName + RuleExpr）。
func AddFingerprint(f *Fingerprint) (created bool, err error) {
	var existing Fingerprint
	result := DB.Where("product_name = ? AND rule_expr = ?", f.ProductName, f.RuleExpr).First(&existing)
	if result.Error == nil {
		return false, nil // 已存在
	}
	if err := DB.Create(f).Error; err != nil {
		return false, err
	}
	return true, nil
}

// ListFingerprints 按条件查询指纹。
func ListFingerprints(product, category, source string, enabledOnly bool, limit, offset int) ([]Fingerprint, int64, error) {
	q := DB.Model(&Fingerprint{})
	if product != "" {
		q = q.Where("product_name LIKE ?", "%"+product+"%")
	}
	if category != "" {
		q = q.Where("category = ?", category)
	}
	if source != "" {
		q = q.Where("source = ?", source)
	}
	if enabledOnly {
		q = q.Where("enabled = ?", true)
	}

	var total int64
	q.Count(&total)

	var fingers []Fingerprint
	if limit <= 0 {
		limit = 50
	}
	err := q.Order("product_name").Limit(limit).Offset(offset).Find(&fingers).Error
	return fingers, total, err
}

// CountFingerprints 统计指纹数量。
func CountFingerprints() (total int64, bySource map[string]int64) {
	DB.Model(&Fingerprint{}).Count(&total)
	bySource = make(map[string]int64)
	var results []struct {
		Source string
		Count  int64
	}
	DB.Model(&Fingerprint{}).Select("source, count(*) as count").Group("source").Scan(&results)
	for _, r := range results {
		bySource[r.Source] = r.Count
	}
	return
}

// DeleteFingerprint 按 ProductName + RuleExpr 删除。
func DeleteFingerprint(product, rule string) (int64, error) {
	result := DB.Where("product_name = ? AND rule_expr = ?", product, rule).Delete(&Fingerprint{})
	return result.RowsAffected, result.Error
}

// GetAllEnabledFingerprints 获取所有启用的指纹（扫描时使用）。
func GetAllEnabledFingerprints() ([]Fingerprint, error) {
	var fingers []Fingerprint
	err := DB.Where("enabled = ?", true).Find(&fingers).Error
	return fingers, err
}

// ---------- Poc CRUD ----------

// AddPoc 添加或更新一个 POC（按 Name 去重）。
func AddPoc(p *Poc) (created bool, err error) {
	var existing Poc
	result := DB.Where("name = ?", p.Name).First(&existing)
	if result.Error == nil {
		// 已存在，更新内容
		existing.Content = p.Content
		existing.ContentHash = p.ContentHash
		existing.Severity = p.Severity
		existing.ExecutionClass = p.ExecutionClass
		existing.RiskLevel = p.RiskLevel
		existing.Tags = p.Tags
		existing.Author = p.Author
		existing.Description = p.Description
		existing.FileName = p.FileName
		if err := DB.Save(&existing).Error; err != nil {
			return false, err
		}
		return false, nil
	}
	if err := DB.Create(p).Error; err != nil {
		return false, err
	}
	return true, nil
}

// ListPocs 按条件查询 POC（不返回 Content 字段）。
func ListPocs(name, severity, source string, enabledOnly bool, limit, offset int) ([]Poc, int64, error) {
	q := DB.Model(&Poc{})
	if name != "" {
		q = q.Where("name LIKE ?", "%"+name+"%")
	}
	if severity != "" {
		q = q.Where("severity = ?", severity)
	}
	if source != "" {
		q = q.Where("source = ?", source)
	}
	if enabledOnly {
		q = q.Where("enabled = ?", true)
	}

	var total int64
	q.Count(&total)

	var pocs []Poc
	if limit <= 0 {
		limit = 50
	}
	// 不选 content 字段，减少内存
	err := q.Select("id, name, file_name, content_hash, severity, execution_class, risk_level, tags, author, description, enabled, source, created_at, updated_at").
		Order("name").Limit(limit).Offset(offset).Find(&pocs).Error
	return pocs, total, err
}

// GetPocByName 获取 POC 详情（含 Content）。
func GetPocByName(name string) (*Poc, error) {
	var poc Poc
	err := DB.Where("name = ?", name).First(&poc).Error
	if err != nil {
		return nil, err
	}
	return &poc, nil
}

// DeletePoc 按名称删除 POC。
func DeletePoc(name string) (int64, error) {
	result := DB.Where("name = ?", name).Delete(&Poc{})
	return result.RowsAffected, result.Error
}

// CountPocs 统计 POC 数量。
func CountPocs() (total int64, bySeverity map[string]int64) {
	DB.Model(&Poc{}).Count(&total)
	bySeverity = make(map[string]int64)
	var results []struct {
		Severity string
		Count    int64
	}
	DB.Model(&Poc{}).Select("severity, count(*) as count").Group("severity").Scan(&results)
	for _, r := range results {
		bySeverity[r.Severity] = r.Count
	}
	return
}

// GetAllEnabledPocs 获取所有启用的 POC（扫描时使用）。
func GetAllEnabledPocs() ([]Poc, error) {
	var pocs []Poc
	err := DB.Where("enabled = ?", true).Find(&pocs).Error
	return pocs, err
}

// GetAllEnabledPocAssets 获取所有启用的 POC 辅助文件资产（扫描物化时使用）。
func GetAllEnabledPocAssets() ([]PocAsset, error) {
	var assets []PocAsset
	err := DB.Where("enabled = ?", true).Order("relative_path").Find(&assets).Error
	return assets, err
}

// GetAllEnabledConfigAssets 获取所有启用的运行时配置资产（扫描物化时使用）。
func GetAllEnabledConfigAssets() ([]ConfigAsset, error) {
	var assets []ConfigAsset
	err := DB.Where("enabled = ?", true).Order("relative_path").Find(&assets).Error
	return assets, err
}

// ---------- Workflow CRUD ----------

// AddWorkflow 添加映射（去重：ProductName + PocName + MatchType）。
func AddWorkflow(w *Workflow) (created bool, err error) {
	var existing Workflow
	result := DB.Where("product_name = ? AND poc_name = ? AND match_type = ?",
		w.ProductName, w.PocName, w.MatchType).First(&existing)
	if result.Error == nil {
		return false, nil
	}
	if err := DB.Create(w).Error; err != nil {
		return false, err
	}
	return true, nil
}

// ListWorkflows 按产品名查询映射。
func ListWorkflows(product string, limit, offset int) ([]Workflow, int64, error) {
	q := DB.Model(&Workflow{})
	if product != "" {
		q = q.Where("product_name LIKE ?", "%"+product+"%")
	}
	var total int64
	q.Count(&total)

	var workflows []Workflow
	if limit <= 0 {
		limit = 50
	}
	err := q.Order("product_name, poc_name").Limit(limit).Offset(offset).Find(&workflows).Error
	return workflows, total, err
}

// DeleteWorkflow 删除映射。
func DeleteWorkflow(product, pocName string) (int64, error) {
	result := DB.Where("product_name = ? AND poc_name = ?", product, pocName).Delete(&Workflow{})
	return result.RowsAffected, result.Error
}

// CountWorkflows 统计映射数量。
func CountWorkflows() int64 {
	var count int64
	DB.Model(&Workflow{}).Count(&count)
	return count
}

// GetAllEnabledWorkflows 获取所有启用的 Workflow（扫描时使用）。
func GetAllEnabledWorkflows() ([]Workflow, error) {
	var workflows []Workflow
	err := DB.Where("enabled = ?", true).Find(&workflows).Error
	return workflows, err
}

// ---------- DirProbe CRUD ----------

// AddDirProbe 添加探测路径（去重）。
func AddDirProbe(d *DirProbe) (created bool, err error) {
	var existing DirProbe
	result := DB.Where("path = ? AND product_name = ?", d.Path, d.ProductName).First(&existing)
	if result.Error == nil {
		return false, nil
	}
	if err := DB.Create(d).Error; err != nil {
		return false, err
	}
	return true, nil
}

// GetAllEnabledDirProbes 获取所有启用的探测路径（扫描时使用）。
func GetAllEnabledDirProbes() ([]DirProbe, error) {
	var probes []DirProbe
	err := DB.Where("enabled = ?", true).Find(&probes).Error
	return probes, err
}

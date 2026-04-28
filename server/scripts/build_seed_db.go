package main

import (
	"crypto/md5"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/user/dddd-server/internal/db"
)

func main() {
	// The script is run from the root directory during build.sh
	configBaseDir := filepath.Join("scanner", "common", "config")
	if _, err := os.Stat(configBaseDir); err != nil {
		log.Fatalf("配置目录未找到: %s", configBaseDir)
	}

	outDir := "deploy"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("创建输出目录失败: %v", err)
	}

	dbPath := filepath.Join(outDir, "arsenal_seed.db")
	_ = os.Remove(dbPath) // 重新生成

	sdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatalf("无法打开临时 SQLite 数据库: %v", err)
	}

	// 自动建表（使用 server/internal/db 中的标准模型）
	if err := sdb.AutoMigrate(&db.Arsenal{}); err != nil {
		log.Fatalf("无法建表: %v", err)
	}

	total := 0
	errs := []error{}

	// 1. finger.yaml
	if data, err := os.ReadFile(filepath.Join(configBaseDir, "finger.yaml")); err == nil {
		if err := writeToDB(sdb, "finger", "finger.yaml", string(data)); err != nil {
			errs = append(errs, err)
		} else {
			total++
		}
	}

	// 2. workflow.yaml
	if data, err := os.ReadFile(filepath.Join(configBaseDir, "workflow.yaml")); err == nil {
		if err := writeToDB(sdb, "workflow", "workflow.yaml", string(data)); err != nil {
			errs = append(errs, err)
		} else {
			total++
		}
	}

	// 3. dir.yaml
	if data, err := os.ReadFile(filepath.Join(configBaseDir, "dir.yaml")); err == nil {
		if err := writeToDB(sdb, "dir", "dir.yaml", string(data)); err != nil {
			errs = append(errs, err)
		} else {
			total++
		}
	}

	// 4. pocs/ 目录
	pocDir := filepath.Join(configBaseDir, "pocs")
	if stat, err := os.Stat(pocDir); err == nil && stat.IsDir() {
		filepath.Walk(pocDir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if info.IsDir() || !strings.HasSuffix(info.Name(), ".yaml") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				errs = append(errs, fmt.Errorf("read poc file failed at %s: %w", path, readErr))
				return nil
			}
			if err := writeToDB(sdb, "poc", info.Name(), string(data)); err != nil {
				errs = append(errs, err)
				return nil
			}
			total++
			return nil
		})
	}

	if len(errs) > 0 {
		log.Printf("⚠️ 编译过程中遇到 %d 个错误，第一个错误: %v", len(errs), errs[0])
	}

	// 关闭连接
	sqlDB, _ := sdb.DB()
	if sqlDB != nil {
		sqlDB.Close()
	}

	log.Printf("🎉 成功将 %d 个规则文件打包入 %s", total, dbPath)
}

func writeToDB(sdb *gorm.DB, typ, fileName, content string) error {
	typ = db.CanonicalArsenalType(typ)
	hash := fmt.Sprintf("%x", md5.Sum([]byte(content)))
	arsenal := db.Arsenal{
		ID:        db.BuildTenantArsenalID("default", typ, fileName),
		TenantID:  "default",
		Type:      typ,
		FileName:  fileName,
		Content:   content,
		Hash:      hash,
		State:     "Approved",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := sdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"content", "hash", "state", "updated_at"}),
	}).Create(&arsenal).Error; err != nil {
		return fmt.Errorf("seed %s/%s failed: %w", typ, fileName, err)
	}
	return nil
}

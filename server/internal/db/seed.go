package db

import (
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SeedArsenalFromDisk 从磁盘上的 scanner/common/config/ 目录读取规则库数据,
// 导入到 PostgreSQL 的 arsenals 表中。
// 按类型增量补种：已有的类型跳过，缺失的类型补上。
func SeedArsenalFromDisk(configBaseDir string) error {
	// 按类型分别检查，只补种缺失的类型
	needsSeed := make(map[string]bool)
	for _, typ := range []string{"finger", "workflow", "dir", "poc"} {
		var count int64
		DB.Model(&Arsenal{}).Where("type = ?", typ).Count(&count)
		if count == 0 {
			needsSeed[typ] = true
		}
	}
	if len(needsSeed) == 0 {
		log.Println("[Seed] All arsenal types already seeded, skipping.")
		return nil
	}
	log.Printf("[Seed] Types needing seed: %v", needsSeed)

	var total int
	var errs []error
	tx := DB.Begin()
	if tx.Error != nil {
		return fmt.Errorf("begin arsenal seed transaction failed: %w", tx.Error)
	}

	// 1. finger.yaml → type=finger
	if needsSeed["finger"] {
		fingerPath := filepath.Join(configBaseDir, "finger.yaml")
		if data, err := os.ReadFile(fingerPath); err == nil {
			if err := seedSingleFile(tx, "finger", "finger.yaml", string(data)); err != nil {
				errs = append(errs, err)
			} else {
				total++
			}
			log.Printf("[Seed] ✅ Fingerprint: imported %d bytes from finger.yaml", len(data))
		} else {
			errs = append(errs, fmt.Errorf("finger.yaml not found at %s: %w", fingerPath, err))
		}
	}

	// 2. workflow.yaml → type=workflow
	if needsSeed["workflow"] {
		workflowPath := filepath.Join(configBaseDir, "workflow.yaml")
		if data, err := os.ReadFile(workflowPath); err == nil {
			if err := seedSingleFile(tx, "workflow", "workflow.yaml", string(data)); err != nil {
				errs = append(errs, err)
			} else {
				total++
			}
			log.Printf("[Seed] ✅ Workflow: imported %d bytes from workflow.yaml", len(data))
		} else {
			errs = append(errs, fmt.Errorf("workflow.yaml not found at %s: %w", workflowPath, err))
		}
	}

	// 3. dir.yaml → type=dir
	if needsSeed["dir"] {
		dirPath := filepath.Join(configBaseDir, "dir.yaml")
		if data, err := os.ReadFile(dirPath); err == nil {
			if err := seedSingleFile(tx, "dir", "dir.yaml", string(data)); err != nil {
				errs = append(errs, err)
			} else {
				total++
			}
			log.Printf("[Seed] ✅ DirProbe: imported %d bytes from dir.yaml", len(data))
		} else {
			errs = append(errs, fmt.Errorf("dir.yaml not found at %s: %w", dirPath, err))
		}
	}

	// 4. pocs/ 目录 → type=poc, 每个 .yaml 文件一条记录
	if needsSeed["poc"] {
		pocDir := filepath.Join(configBaseDir, "pocs")
		if stat, err := os.Stat(pocDir); err == nil && stat.IsDir() {
			pocCount := 0
			err := filepath.Walk(pocDir, func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					errs = append(errs, fmt.Errorf("walk pocs directory failed at %s: %w", path, walkErr))
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
				if err := seedSingleFile(tx, "poc", info.Name(), string(data)); err != nil {
					errs = append(errs, err)
					return nil
				}
				pocCount++
				return nil
			})
			if err != nil {
				errs = append(errs, fmt.Errorf("walk pocs directory failed: %w", err))
			}
			if pocCount == 0 {
				errs = append(errs, fmt.Errorf("no poc templates found under %s", pocDir))
			}
			total += pocCount
			log.Printf("[Seed] ✅ POC: imported %d templates from pocs/", pocCount)
		} else {
			errs = append(errs, fmt.Errorf("pocs directory not found at %s", pocDir))
		}
	}

	if len(errs) > 0 {
		tx.Rollback()
		return errors.Join(errs...)
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("commit arsenal seed transaction failed: %w", err)
	}

	log.Printf("[Seed] 🎉 Arsenal seeding complete. Total new records: %d", total)
	return nil
}

func seedSingleFile(tx *gorm.DB, typ, fileName, content string) error {
	typ = CanonicalArsenalType(typ)
	hash := fmt.Sprintf("%x", md5.Sum([]byte(content)))
	arsenal := Arsenal{
		ID:        BuildTenantArsenalID("default", typ, fileName),
		TenantID:  "default",
		Type:      typ,
		FileName:  fileName,
		Content:   content,
		Hash:      hash,
		State:     "Approved",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	// 使用 Upsert 防止唯一键冲突导致事务 abort (SQLSTATE 25P02)
	if err := tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"content", "hash", "state", "updated_at"}),
	}).Create(&arsenal).Error; err != nil {
		return fmt.Errorf("seed %s/%s failed: %w", typ, fileName, err)
	}
	return nil
}

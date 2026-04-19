package db

import (
	"crypto/md5"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SeedArsenalFromDisk 从磁盘上的 scanner/common/config/ 目录读取规则库数据,
// 导入到 PostgreSQL 的 arsenals 表中。仅在第一次运行（表为空）时批量导入。
func SeedArsenalFromDisk(configBaseDir string) {
	var count int64
	DB.Model(&Arsenal{}).Count(&count)
	if count > 0 {
		log.Printf("[Seed] Arsenal table already has %d records, skipping seed.", count)
		return
	}

	log.Println("[Seed] Arsenal table is empty. Seeding from disk...")

	var total int

	// 1. finger.yaml → type=finger
	fingerPath := filepath.Join(configBaseDir, "finger.yaml")
	if data, err := os.ReadFile(fingerPath); err == nil {
		n := seedSingleFile("finger", "finger.yaml", string(data))
		total += n
		log.Printf("[Seed] ✅ Fingerprint: imported %d bytes from finger.yaml", len(data))
	} else {
		log.Printf("[Seed] ⚠ finger.yaml not found at %s: %v", fingerPath, err)
	}

	// 2. workflow.yaml → type=workflow
	workflowPath := filepath.Join(configBaseDir, "workflow.yaml")
	if data, err := os.ReadFile(workflowPath); err == nil {
		n := seedSingleFile("workflow", "workflow.yaml", string(data))
		total += n
		log.Printf("[Seed] ✅ Workflow: imported %d bytes from workflow.yaml", len(data))
	} else {
		log.Printf("[Seed] ⚠ workflow.yaml not found at %s: %v", workflowPath, err)
	}

	// 3. dir.yaml → type=dir
	dirPath := filepath.Join(configBaseDir, "dir.yaml")
	if data, err := os.ReadFile(dirPath); err == nil {
		n := seedSingleFile("dir", "dir.yaml", string(data))
		total += n
		log.Printf("[Seed] ✅ DirProbe: imported %d bytes from dir.yaml", len(data))
	} else {
		log.Printf("[Seed] ⚠ dir.yaml not found at %s: %v", dirPath, err)
	}

	// 4. pocs/ 目录 → type=poc, 每个 .yaml 文件一条记录
	pocDir := filepath.Join(configBaseDir, "pocs")
	if stat, err := os.Stat(pocDir); err == nil && stat.IsDir() {
		pocCount := 0
		err := filepath.Walk(pocDir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if info.IsDir() || !strings.HasSuffix(info.Name(), ".yaml") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			seedSingleFile("poc", info.Name(), string(data))
			pocCount++
			return nil
		})
		if err != nil {
			log.Printf("[Seed] ⚠ Error walking pocs directory: %v", err)
		}
		total += pocCount
		log.Printf("[Seed] ✅ POC: imported %d templates from pocs/", pocCount)
	} else {
		log.Printf("[Seed] ⚠ pocs/ directory not found at %s", pocDir)
	}

	log.Printf("[Seed] 🎉 Arsenal seeding complete. Total records: %d", total)
}

func seedSingleFile(typ, fileName, content string) int {
	typ = CanonicalArsenalType(typ)
	hash := fmt.Sprintf("%x", md5.Sum([]byte(content)))
	arsenal := Arsenal{
		ID:        BuildArsenalID(typ, fileName),
		TenantID:  "default",
		Type:      typ,
		FileName:  fileName,
		Content:   content,
		Hash:      hash,
		State:     "Approved",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := DB.Create(&arsenal).Error; err != nil {
		log.Printf("[Seed] Failed to seed %s/%s: %v", typ, fileName, err)
		return 0
	}
	return 1
}

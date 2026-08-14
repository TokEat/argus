package db

import (
	"crypto/md5"
	"fmt"
	"log"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SeedArsenalFromSQLite 从本地预编译的 SQLite 数据库读取规则资产，并导入到 PostgreSQL。
func SeedArsenalFromSQLite(dbPath string) error {
	log.Printf("[Seed] Connecting to local SQLite DB: %s", dbPath)
	sdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("open sqlite db failed: %w", err)
	}
	defer func() {
		sqlDB, _ := sdb.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	var arsenals []Arsenal
	if err := sdb.Find(&arsenals).Error; err != nil {
		return fmt.Errorf("read arsenals from sqlite failed: %w", err)
	}

	if len(arsenals) == 0 {
		log.Println("[Seed] No records found in SQLite DB.")
		return nil
	}

	sanitizedCount := 0
	for i := range arsenals {
		if sanitizeArsenalTextFields(&arsenals[i]) {
			sanitizedCount++
		}
	}
	if sanitizedCount > 0 {
		log.Printf("[Seed] Normalized PostgreSQL text in %d rule records before import.", sanitizedCount)
	}

	log.Printf("[Seed] Found %d records, starting Upsert...", len(arsenals))

	if err := DB.Transaction(func(tx *gorm.DB) error {
		filtered, err := prepareShiroActiveFingerprintMigration(tx, arsenals)
		if err != nil {
			return err
		}
		if len(filtered) == 0 {
			return nil
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"content", "hash", "state", "updated_at"}),
		}).CreateInBatches(filtered, 200).Error
	}); err != nil {
		return fmt.Errorf("upsert arsenals to postgres failed: %w", err)
	}

	log.Printf("[Seed] 🎉 Arsenal seeding complete. Total records: %d", len(arsenals))

	log.Println("[Seed] Normalizing legacy types and syncing structured rule catalog...")
	if err := normalizeLegacyArsenalTypes(); err != nil {
		return fmt.Errorf("normalize legacy arsenal types failed: %w", err)
	}
	if err := SyncRuleCatalogFromArsenal(); err != nil {
		return fmt.Errorf("sync structured rule catalog failed: %w", err)
	}
	log.Println("[Seed] Rule catalog sync complete.")

	return nil
}

const (
	legacyShiroPOCMD5      = "7774baad68d35d51457514f81de51b53"
	legacyShiroWorkflowMD5 = "02854e9cb1e8bcceb2779e6bf7507e1a"
	activeShiroWorkflowMD5 = "93477c20f770d573528d7df5085f239e"
	previousShiroProbeMD5  = "b17c2311ae032f502a4fc258129e50a4"
	activeShiroProbeMD5    = "72e331ff053fc10956c73804502c6994"
)

// prepareShiroActiveFingerprintMigration applies the built-in Shiro move only
// when every touched artifact is still an exact known built-in. A custom POC,
// workflow, or same-name active probe makes the migration fail closed for that
// tenant while unrelated seed artifacts continue to import.
func prepareShiroActiveFingerprintMigration(tx *gorm.DB, incoming []Arsenal) ([]Arsenal, error) {
	byTenant := map[string]map[string]int{}
	for index := range incoming {
		row := incoming[index]
		tenantID := strings.TrimSpace(row.TenantID)
		if tenantID == "" {
			tenantID = "default"
		}
		key := CanonicalArsenalType(row.Type) + "/" + row.FileName
		if byTenant[tenantID] == nil {
			byTenant[tenantID] = map[string]int{}
		}
		byTenant[tenantID][key] = index
	}
	skip := map[int]bool{}
	for tenantID, indexes := range byTenant {
		activeIndex, hasActive := indexes["active_fingerprint/shiro-detect.yaml"]
		workflowIndex, hasWorkflow := indexes["workflow/workflow.yaml"]
		if !hasActive || !hasWorkflow || arsenalContentMD5(incoming[activeIndex]) != activeShiroProbeMD5 || arsenalContentMD5(incoming[workflowIndex]) != activeShiroWorkflowMD5 {
			continue
		}

		conflicts := make([]string, 0, 3)
		var existingActive Arsenal
		if err := tx.Where("tenant_id = ? AND type IN ? AND file_name = ?", tenantID, ArsenalTypeAliases("active_fingerprint"), "shiro-detect.yaml").First(&existingActive).Error; err == nil {
			hash := arsenalContentMD5(existingActive)
			if hash != activeShiroProbeMD5 && hash != previousShiroProbeMD5 {
				conflicts = append(conflicts, "active-fingerprints/shiro-detect.yaml is tenant-customized")
			}
		} else if err != gorm.ErrRecordNotFound {
			return nil, err
		}

		var existingWorkflow Arsenal
		if err := tx.Where("tenant_id = ? AND type IN ? AND file_name = ?", tenantID, ArsenalTypeAliases("workflow"), "workflow.yaml").First(&existingWorkflow).Error; err == nil {
			hash := arsenalContentMD5(existingWorkflow)
			if hash != legacyShiroWorkflowMD5 && hash != activeShiroWorkflowMD5 {
				conflicts = append(conflicts, "workflow.yaml is tenant-customized")
			}
		} else if err != gorm.ErrRecordNotFound {
			return nil, err
		}

		var legacyPOC Arsenal
		pocFound := false
		if err := tx.Where("tenant_id = ? AND type IN ? AND file_name = ?", tenantID, ArsenalTypeAliases("poc"), "shiro-detect.yaml").First(&legacyPOC).Error; err == nil {
			pocFound = true
			if arsenalContentMD5(legacyPOC) != legacyShiroPOCMD5 {
				conflicts = append(conflicts, "pocs/shiro-detect.yaml is tenant-customized")
			}
		} else if err != gorm.ErrRecordNotFound {
			return nil, err
		}

		if len(conflicts) > 0 {
			skip[activeIndex], skip[workflowIndex] = true, true
			log.Printf("[Seed][MigrationConflict] tenant=%s Shiro active fingerprint migration skipped: %s", tenantID, strings.Join(conflicts, "; "))
			continue
		}
		if pocFound {
			if err := tx.Delete(&Arsenal{}, "tenant_id = ? AND id = ?", tenantID, legacyPOC.ID).Error; err != nil {
				return nil, err
			}
			log.Printf("[Seed] tenant=%s migrated unmodified built-in Shiro POC to active fingerprint", tenantID)
		}
	}
	filtered := make([]Arsenal, 0, len(incoming))
	for index, row := range incoming {
		if !skip[index] {
			filtered = append(filtered, row)
		}
	}
	return filtered, nil
}

func arsenalContentMD5(row Arsenal) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(row.Content)))
}

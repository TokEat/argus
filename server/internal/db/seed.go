package db

import (
	"fmt"
	"log"

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

	if err := DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"content", "hash", "state", "updated_at"}),
	}).CreateInBatches(arsenals, 200).Error; err != nil {
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

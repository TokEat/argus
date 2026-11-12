package db

import (
	"fmt"
	"log"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const DefaultPostgresDSN = "host=127.0.0.1 user=postgres password=argus_dev_pg_S7m9Q4r2L8xP6nV3 dbname=argus port=5432 sslmode=disable"

func normalizePostgresDSN(dsn string) string {
	if strings.TrimSpace(dsn) == "" {
		return DefaultPostgresDSN
	}
	return strings.TrimSpace(dsn)
}

func OpenDB(dsn string) (*gorm.DB, error) {
	normalized := normalizePostgresDSN(dsn)
	db, err := gorm.Open(postgres.Open(normalized), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("initialize PostgreSQL database: %w", err)
	}
	return db, nil
}

func SetDB(db *gorm.DB) {
	DB = db
}

// InitDB 打开数据库并做启动期校验（不执行任何迁移）。
// 初始化/升级由 deploy/db-init.sh（纯 SQL 导入）负责。
func InitDB(dsn string) {
	if strings.TrimSpace(dsn) == "" {
		log.Printf("No DSN provided, using default PostgreSQL DSN: %s", DefaultPostgresDSN)
	}

	db, err := OpenDB(dsn)
	if err != nil {
		log.Fatalf("failed to initialize PostgreSQL database: %v", err)
	}
	SetDB(db)

	if err := VerifyDatabaseReady(db); err != nil {
		log.Fatalf("database not ready: %v", err)
	}

	log.Printf("PostgreSQL database verified (schema version >= %s).", RequiredSchemaVersion)
}

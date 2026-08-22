package db

import (
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"
)

// RequiredSchemaVersion 声明本二进制运行所需的最低数据库 schema 版本。
// 版本记录由 deploy/db-init.sh（纯 SQL 导入）写入 schema_migrations 表；
// server 启动时只校验、不迁移。schema 变更流程见 deploy/db/README.md：
// 新增 deploy/db/init/NNN_xxx.sql 并将本常量同步推进到 NNN。
const RequiredSchemaVersion = "002"

// SchemaMigration 映射 schema_migrations 表（由 deploy/db-init.sh 维护）。
type SchemaMigration struct {
	Version   string `gorm:"primaryKey"`
	Name      string
	Checksum  string
	AppliedAt time.Time
}

func (SchemaMigration) TableName() string {
	return "schema_migrations"
}

// VerifySchemaVersion 校验 schema_migrations 已记录本版本所需的 schema。
// 版本记录是累积的（init 文件按序追加且版本号不复用），因此存在
// RequiredSchemaVersion 行即代表该版本及之前全部 schema 已就位。
// 失败时返回的错误包含初始化指引，调用方应直接终止启动。
func VerifySchemaVersion(conn *gorm.DB) error {
	var count int64
	if err := conn.Table("schema_migrations").
		Where("version = ?", RequiredSchemaVersion).
		Count(&count).Error; err != nil {
		return fmt.Errorf(
			"无法读取 schema_migrations（%w）。数据库可能未初始化：请先运行 deploy/db-init.sh（开发环境可用 make db-setup）后再启动 argus-server",
			err,
		)
	}
	if count == 0 {
		return fmt.Errorf(
			"数据库 schema 版本不满足要求（需要 >= %s）。请先运行 deploy/db-init.sh（开发环境可用 make db-setup）完成数据库初始化/升级；argus-server 启动时不再执行迁移",
			RequiredSchemaVersion,
		)
	}
	return nil
}

// VerifyDatabaseReady 是启动期数据库校验的唯一入口：
// 版本记录 + 表/列/索引契约全部通过才允许对外提供服务。
func VerifyDatabaseReady(conn *gorm.DB) error {
	if err := VerifySchemaVersion(conn); err != nil {
		return err
	}
	if err := VerifySchema(conn); err != nil {
		return fmt.Errorf(
			"数据库结构契约校验失败（%w）。请运行 deploy/db-init.sh 将数据库升级到与本二进制匹配的 schema 后重启",
			err,
		)
	}
	return nil
}

// OpenDBWithRetry 在超时时间内反复尝试连接，用于 server 启动等待外部 PostgreSQL 就绪。
// timeout <= 0 时使用默认 30s；--migrate 场景请直接使用 OpenDB（由脚本侧等待）。
func OpenDBWithRetry(dsn string, timeout time.Duration) (*gorm.DB, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		conn, err := OpenDB(dsn)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("连接 PostgreSQL 超时（%s）: %w", timeout, lastErr)
		}
		log.Printf("等待 PostgreSQL 就绪（%v 后放弃）: %v", time.Until(deadline).Round(time.Second), err)
		time.Sleep(2 * time.Second)
	}
}

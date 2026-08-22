package db

import (
	"os"
	"strings"
	"testing"
)

// 静态守卫：deploy/db 的初始化 SQL 必须存在且自记 RequiredSchemaVersion，
// 防止版本常量与 SQL 文件脱节。无需数据库，任何环境都会执行。
func TestInitSQLStampsRequiredVersion(t *testing.T) {
	root := "../../.."
	if _, err := os.Stat(root + "/go.mod"); err != nil {
		t.Fatalf("cannot locate repo root: %v", err)
	}
	sqlPath := root + "/deploy/db/init/001_init.sql"
	content, err := os.ReadFile(sqlPath)
	if err != nil {
		t.Fatalf("deploy/db/init/001_init.sql is missing: %v", err)
	}
	sql := string(content)
	want := "VALUES ('" + RequiredSchemaVersion + "', 'init_baseline', 'psql-managed', now())"
	if !strings.Contains(sql, want) {
		t.Fatalf("init SQL does not stamp required version %q (looked for %q)", RequiredSchemaVersion, want)
	}
	for _, banned := range []string{
		"CREATE TABLE public.cron_tasks",
		"CREATE TABLE public.notification_rules",
		"CREATE TABLE public.asset_change_logs",
		"CREATE VIEW public.tenant_quota",
	} {
		if strings.Contains(sql, banned) {
			t.Fatalf("init SQL still contains dropped legacy object: %q", banned)
		}
	}
}

// 真实库校验（make db-verify 注入 ARGUS_VERIFY_DSN，指向由 deploy/db/init/*.sql
// 导入完成的库）：版本校验 + 结构契约必须全部通过。
func TestVerifyDatabaseReadyOnInitSQLDatabase(t *testing.T) {
	dsn := os.Getenv("ARGUS_VERIFY_DSN")
	if dsn == "" {
		t.Skip("ARGUS_VERIFY_DSN not set; run via make db-verify")
	}
	conn, err := OpenDB(dsn)
	if err != nil {
		t.Fatalf("open verify dsn: %v", err)
	}
	if err := VerifyDatabaseReady(conn); err != nil {
		t.Fatalf("VerifyDatabaseReady failed on init-SQL database: %v", err)
	}
}

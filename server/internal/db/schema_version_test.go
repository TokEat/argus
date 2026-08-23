package db

import (
	"os"
	"path/filepath"
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
	initFiles, err := filepath.Glob(root + "/deploy/db/init/[0-9]*.sql")
	if err != nil || len(initFiles) == 0 {
		t.Fatalf("deploy/db/init SQL files are missing: %v", err)
	}
	versionPrefix := strings.SplitN(RequiredSchemaVersion, "_", 2)[0]
	stamped := false
	for _, sqlPath := range initFiles {
		content, err := os.ReadFile(sqlPath)
		if err != nil {
			t.Fatalf("read %s failed: %v", sqlPath, err)
		}
		sql := string(content)
		if strings.HasPrefix(filepath.Base(sqlPath), versionPrefix+"_") {
			if !strings.Contains(sql, "VALUES ('"+RequiredSchemaVersion+"', '") ||
				!strings.Contains(sql, ", 'psql-managed', now())") {
				t.Fatalf("%s must self-stamp version %q with psql-managed checksum", filepath.Base(sqlPath), RequiredSchemaVersion)
			}
			stamped = true
		}
		for _, banned := range []string{
			"CREATE TABLE public.cron_tasks",
			"CREATE TABLE public.notification_rules",
			"CREATE TABLE public.asset_change_logs",
			"CREATE VIEW public.tenant_quota",
		} {
			if strings.Contains(sql, banned) {
				t.Fatalf("%s still contains dropped legacy object: %q", filepath.Base(sqlPath), banned)
			}
		}
	}
	if !stamped {
		t.Fatalf("no init SQL file matches required version %q", RequiredSchemaVersion)
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

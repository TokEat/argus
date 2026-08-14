package db

import (
	"os"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestHistoricalVersion510RecordsCanAdvanceTo560(t *testing.T) {
	adminDSN, admin := openTestPostgres(t)
	cases := []struct {
		name           string
		migrationName  string
		checksum       string
		seedScanPolicy bool
	}{
		{
			name:          "remove python EXP history",
			migrationName: "remove_python_exp",
			checksum:      "418f612bbe1f049e72898b07ce0ef1c481dd107ebd7c01012b16deddb97c2049",
		},
		{
			name:           "scan policy orchestration history",
			migrationName:  "add_scan_policy_orchestration",
			checksum:       "a38db3ede5e22c02a17e33bbdc47328bd07f5fea8d709bd3cb1737e00c3f7e3e",
			seedScanPolicy: true,
		},
	}

	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := "argus_it_legacy_510_" + string(rune('a'+index))
			recreateTestDatabase(t, admin, name)
			conn, err := OpenDB(withDSNDatabase(adminDSN, name))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeTestDB(t, conn) })

			if err := ensureSchemaMigrationsTable(conn); err != nil {
				t.Fatal(err)
			}
			if tc.seedScanPolicy {
				sql, err := migrationFS.ReadFile("migrations/560_add_scan_policy_orchestration.sql")
				if err != nil {
					t.Fatal(err)
				}
				if err := applySQLScript(conn, "historical-510-scan-policy", string(sql)); err != nil {
					t.Fatal(err)
				}
			}
			legacy := SchemaMigration{
				Version:   "510",
				Name:      tc.migrationName,
				Checksum:  tc.checksum,
				AppliedAt: time.Now(),
			}
			if err := conn.Create(&legacy).Error; err != nil {
				t.Fatal(err)
			}

			t.Setenv(forceIncrementalEnv, "1")
			if err := ApplyMigrations(conn, MigrationModeApply); err != nil {
				t.Fatalf("advance historical 510 database: %v", err)
			}
			if err := VerifySchema(conn); err != nil {
				t.Fatalf("verify advanced schema: %v", err)
			}

			applied, err := loadAppliedMigrations(conn)
			if err != nil {
				t.Fatal(err)
			}
			if got := applied["510"]; got.Name != tc.migrationName || got.Checksum != tc.checksum {
				t.Fatalf("historical 510 record was rewritten: %+v", got)
			}
			if got := applied["560"]; got.Name != "add_scan_policy_orchestration" || got.Checksum == "" {
				t.Fatalf("migration 560 was not recorded: %+v", got)
			}
			for _, table := range []string{
				"scan_policy_intents",
				"scan_stage_derivations",
				"credential_dictionaries",
				"credential_dictionary_revisions",
				"credential_bundles",
				"credential_finding_secrets",
				"credential_reveal_audits",
			} {
				if !conn.Migrator().HasTable(table) {
					t.Fatalf("expected table %s after migration 560", table)
				}
			}
		})
	}
}

func TestForceIncrementalMigrations(t *testing.T) {
	t.Setenv(forceIncrementalEnv, "")
	if forceIncrementalMigrations() {
		t.Fatal("empty env should not force incremental")
	}
	t.Setenv(forceIncrementalEnv, "1")
	if !forceIncrementalMigrations() {
		t.Fatal("ARGUS_DB_FORCE_INCREMENTAL=1 should force incremental")
	}
}

func TestLoadBaselineVersionsMatchIncrementalFiles(t *testing.T) {
	versions, err := loadBaselineVersions()
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	byVersion := make(map[string]migrationFile, len(migrations))
	for _, migration := range migrations {
		byVersion[migration.Version] = migration
	}
	for _, version := range versions {
		if _, ok := byVersion[version]; !ok {
			t.Fatalf("baseline version %s is not an incremental migration", version)
		}
	}
	have := make(map[string]struct{}, len(versions))
	for _, version := range versions {
		have[version] = struct{}{}
	}
	tip := versions[len(versions)-1]
	for _, migration := range migrations {
		if migration.Version > tip {
			continue
		}
		if _, ok := have[migration.Version]; !ok {
			t.Fatalf("incremental version %s is older than baseline tip %s but not stamped", migration.Version, tip)
		}
	}
}

func TestBaselineSQLIsPresent(t *testing.T) {
	schemaSQL, err := schemaFS.ReadFile(currentSchemaSQLFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(schemaSQL), "CREATE TABLE public.projects") {
		t.Fatal("current schema baseline is missing projects")
	}
	if strings.Contains(string(schemaSQL), "schema_migrations") {
		t.Fatal("current schema baseline must not define schema_migrations")
	}
	seedSQL, err := schemaFS.ReadFile(currentSchemaSeedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(seedSQL), "INSERT INTO users") {
		t.Fatal("dev seed baseline is missing admin insert")
	}
}

func TestSplitSQLStatementsIgnoresLineComments(t *testing.T) {
	sql := `
-- comment with a semicolon;
CREATE TABLE foo (id INT);
-- another;
ALTER TABLE foo ADD COLUMN name TEXT;
`
	stmts := splitSQLStatements(sql)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d: %#v", len(stmts), stmts)
	}
}

func TestEmptyDatabaseAppliesBaseline(t *testing.T) {
	adminDSN, admin := openTestPostgres(t)
	name := "argus_it_baseline"
	recreateTestDatabase(t, admin, name)
	conn, err := OpenDB(withDSNDatabase(adminDSN, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestDB(t, conn) })

	t.Setenv(forceIncrementalEnv, "")
	if err := ApplyMigrations(conn, MigrationModeApply); err != nil {
		t.Fatalf("baseline apply: %v", err)
	}
	if err := VerifySchema(conn); err != nil {
		t.Fatalf("baseline verify: %v", err)
	}

	versions, err := loadBaselineVersions()
	if err != nil {
		t.Fatal(err)
	}
	applied, err := loadAppliedMigrations(conn)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range versions {
		if _, ok := applied[version]; !ok {
			t.Fatalf("baseline did not stamp version %s", version)
		}
	}

	var adminCount int64
	if err := conn.Table("users").Where("username = ?", "admin").Count(&adminCount).Error; err != nil {
		t.Fatal(err)
	}
	if adminCount != 1 {
		t.Fatalf("expected seeded admin user, got %d", adminCount)
	}
}

func TestDirtyDatabaseRefusesBaseline(t *testing.T) {
	adminDSN, admin := openTestPostgres(t)
	name := "argus_it_dirty"
	recreateTestDatabase(t, admin, name)
	conn, err := OpenDB(withDSNDatabase(adminDSN, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestDB(t, conn) })

	if err := conn.Exec("CREATE TABLE projects (id text)").Error; err != nil {
		t.Fatal(err)
	}
	t.Setenv(forceIncrementalEnv, "")
	err = ApplyMigrations(conn, MigrationModeApply)
	if err == nil || !strings.Contains(err.Error(), "refusing to apply schema baseline") {
		t.Fatalf("expected dirty-database error, got %v", err)
	}
}

func TestBaselineMatchesIncrementalSchema(t *testing.T) {
	adminDSN, admin := openTestPostgres(t)
	baselineName := "argus_it_baseline_cmp"
	incrementalName := "argus_it_incremental_cmp"
	recreateTestDatabase(t, admin, baselineName)
	recreateTestDatabase(t, admin, incrementalName)

	baseline, err := OpenDB(withDSNDatabase(adminDSN, baselineName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestDB(t, baseline) })
	t.Setenv(forceIncrementalEnv, "")
	if err := ApplyMigrations(baseline, MigrationModeApply); err != nil {
		t.Fatalf("baseline apply: %v", err)
	}
	if err := VerifySchema(baseline); err != nil {
		t.Fatalf("baseline verify: %v", err)
	}

	incremental, err := OpenDB(withDSNDatabase(adminDSN, incrementalName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestDB(t, incremental) })
	t.Setenv(forceIncrementalEnv, "1")
	if err := ApplyMigrations(incremental, MigrationModeApply); err != nil {
		t.Fatalf("incremental apply: %v", err)
	}
	if err := VerifySchema(incremental); err != nil {
		t.Fatalf("incremental verify: %v", err)
	}

	left, err := schemaInventory(baseline)
	if err != nil {
		t.Fatal(err)
	}
	right, err := schemaInventory(incremental)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("baseline schema differs from incremental schema\nbaseline=%s\nincremental=%s", left, right)
	}
}

func openTestPostgres(t *testing.T) (string, *gorm.DB) {
	t.Helper()
	candidates := []string{
		strings.TrimSpace(os.Getenv("ARGUS_TEST_DSN")),
		strings.TrimSpace(os.Getenv("DB_DSN")),
		DefaultPostgresDSN,
		"host=127.0.0.1 user=postgres password=argus_ci dbname=postgres port=5432 sslmode=disable",
	}
	var last error
	for _, dsn := range candidates {
		if dsn == "" {
			continue
		}
		adminDSN := withDSNDatabase(dsn, "postgres")
		db, err := OpenDB(adminDSN)
		if err != nil {
			last = err
			continue
		}
		sqlDB, err := db.DB()
		if err != nil {
			last = err
			closeTestDB(t, db)
			continue
		}
		if err := sqlDB.Ping(); err != nil {
			last = err
			closeTestDB(t, db)
			continue
		}
		t.Cleanup(func() { closeTestDB(t, db) })
		return adminDSN, db
	}
	if last != nil {
		t.Skipf("postgres not available: %v", last)
	}
	t.Skip("postgres not available")
	return "", nil
}

func recreateTestDatabase(t *testing.T, admin *gorm.DB, name string) {
	t.Helper()
	if !isSafeTestDBName(name) {
		t.Fatalf("unsafe test database name %q", name)
	}
	if err := admin.Exec("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ? AND pid <> pg_backend_pid()", name).Error; err != nil {
		t.Fatalf("terminate %s: %v", name, err)
	}
	if err := admin.Exec("DROP DATABASE IF EXISTS " + name).Error; err != nil {
		t.Fatalf("drop %s: %v", name, err)
	}
	if err := admin.Exec("CREATE DATABASE " + name).Error; err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ? AND pid <> pg_backend_pid()", name).Error
		_ = admin.Exec("DROP DATABASE IF EXISTS " + name).Error
	})
}

func closeTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	if db == nil {
		return
	}
	sqlDB, err := db.DB()
	if err != nil {
		return
	}
	_ = sqlDB.Close()
}

func withDSNDatabase(dsn, name string) string {
	parts := strings.Fields(dsn)
	out := make([]string, 0, len(parts)+1)
	found := false
	for _, part := range parts {
		if strings.HasPrefix(part, "dbname=") {
			out = append(out, "dbname="+name)
			found = true
			continue
		}
		out = append(out, part)
	}
	if !found {
		out = append(out, "dbname="+name)
	}
	return strings.Join(out, " ")
}

func isSafeTestDBName(name string) bool {
	if !strings.HasPrefix(name, "argus_it_") {
		return false
	}
	for _, r := range name {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func schemaInventory(db *gorm.DB) (string, error) {
	var columns []string
	if err := db.Raw(`
		SELECT table_name || '.' || column_name || ':' || data_type
		FROM information_schema.columns
		WHERE table_schema = 'public'
		ORDER BY table_name, column_name
	`).Scan(&columns).Error; err != nil {
		return "", err
	}
	var indexes []string
	if err := db.Raw(`
		SELECT tablename || '.' || indexname
		FROM pg_indexes
		WHERE schemaname = 'public'
		ORDER BY tablename, indexname
	`).Scan(&indexes).Error; err != nil {
		return "", err
	}
	var views []string
	if err := db.Raw(`
		SELECT table_name
		FROM information_schema.views
		WHERE table_schema = 'public'
		ORDER BY table_name
	`).Scan(&views).Error; err != nil {
		return "", err
	}
	return "columns=" + strings.Join(columns, ",") +
		"\nindexes=" + strings.Join(indexes, ",") +
		"\nviews=" + strings.Join(views, ","), nil
}

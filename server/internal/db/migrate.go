package db

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

//go:embed schema/000_current_schema.sql schema/000_current_schema.versions schema/001_dev_seed.sql
var schemaFS embed.FS

const (
	forceIncrementalEnv   = "ARGUS_DB_FORCE_INCREMENTAL"
	currentSchemaSQLFile  = "schema/000_current_schema.sql"
	currentSchemaVersions = "schema/000_current_schema.versions"
	currentSchemaSeedFile = "schema/001_dev_seed.sql"
)

type MigrationMode string

const (
	MigrationModeApply   MigrationMode = "apply"
	MigrationModeVerify  MigrationMode = "verify"
	MigrationModeDevAuto MigrationMode = "dev-auto"
)

type SchemaMigration struct {
	Version   string `gorm:"primaryKey"`
	Name      string
	Checksum  string
	AppliedAt time.Time
}

func (SchemaMigration) TableName() string {
	return "schema_migrations"
}

type migrationFile struct {
	Version  string
	Name     string
	Path     string
	Checksum string
	SQL      string
}

func ParseMigrationMode(raw string) (MigrationMode, error) {
	switch MigrationMode(strings.ToLower(strings.TrimSpace(raw))) {
	case "", MigrationModeApply:
		return MigrationModeApply, nil
	case MigrationModeVerify:
		return MigrationModeVerify, nil
	case MigrationModeDevAuto:
		return MigrationModeDevAuto, nil
	default:
		return "", fmt.Errorf("unsupported db migration mode: %s", raw)
	}
}

func ApplyMigrations(db *gorm.DB, mode MigrationMode) error {
	switch mode {
	case MigrationModeVerify:
		return verifyMigrations(db)
	case MigrationModeApply, MigrationModeDevAuto:
	default:
		return fmt.Errorf("unsupported db migration mode: %s", mode)
	}

	if err := ensureSchemaMigrationsTable(db); err != nil {
		return err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	applied, err := loadAppliedMigrations(db)
	if err != nil {
		return err
	}

	if len(applied) == 0 && !forceIncrementalMigrations() {
		tables, err := listApplicationTables(db)
		if err != nil {
			return err
		}
		if len(tables) > 0 {
			return fmt.Errorf(
				"refusing to apply schema baseline: database already has application tables (%s) but schema_migrations is empty",
				strings.Join(tables, ", "),
			)
		}
		if err := applyBaselineSchema(db, migrations); err != nil {
			return err
		}
		applied, err = loadAppliedMigrations(db)
		if err != nil {
			return err
		}
	}

	for _, migration := range migrations {
		if prev, ok := applied[migration.Version]; ok {
			if prev.Checksum != migration.Checksum {
				return fmt.Errorf(
					"migration checksum mismatch for version %s (%s): db=%s code=%s",
					migration.Version,
					migration.Name,
					prev.Checksum,
					migration.Checksum,
				)
			}
			continue
		}

		if err := applyMigrationFile(db, migration); err != nil {
			return err
		}
	}

	if mode == MigrationModeDevAuto {
		if err := autoMigrateSchema(db); err != nil {
			return fmt.Errorf("dev-auto automigrate failed: %w", err)
		}
	}

	if err := ensureRuntimeIndexes(db); err != nil {
		return err
	}

	return nil
}

func forceIncrementalMigrations() bool {
	raw := strings.TrimSpace(os.Getenv(forceIncrementalEnv))
	switch strings.ToLower(raw) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func listApplicationTables(db *gorm.DB) ([]string, error) {
	var names []string
	err := db.Raw(`
		SELECT tablename
		FROM pg_tables
		WHERE schemaname = current_schema()
		  AND tablename <> 'schema_migrations'
		ORDER BY tablename
	`).Scan(&names).Error
	if err != nil {
		return nil, fmt.Errorf("list application tables failed: %w", err)
	}
	return names, nil
}

func loadBaselineVersions() ([]string, error) {
	raw, err := schemaFS.ReadFile(currentSchemaVersions)
	if err != nil {
		return nil, fmt.Errorf("read %s failed: %w", currentSchemaVersions, err)
	}

	var versions []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(raw), "\n") {
		version := strings.TrimSpace(line)
		if version == "" || strings.HasPrefix(version, "#") {
			continue
		}
		if _, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate baseline version %s", version)
		}
		seen[version] = struct{}{}
		versions = append(versions, version)
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("%s does not list any versions", currentSchemaVersions)
	}
	return versions, nil
}

func applyBaselineSchema(db *gorm.DB, migrations []migrationFile) error {
	schemaSQL, err := schemaFS.ReadFile(currentSchemaSQLFile)
	if err != nil {
		return fmt.Errorf("read %s failed: %w", currentSchemaSQLFile, err)
	}
	seedSQL, err := schemaFS.ReadFile(currentSchemaSeedFile)
	if err != nil {
		return fmt.Errorf("read %s failed: %w", currentSchemaSeedFile, err)
	}
	versions, err := loadBaselineVersions()
	if err != nil {
		return err
	}

	byVersion := make(map[string]migrationFile, len(migrations))
	for _, migration := range migrations {
		if _, exists := byVersion[migration.Version]; exists {
			return fmt.Errorf("duplicate incremental migration version %s", migration.Version)
		}
		byVersion[migration.Version] = migration
	}

	stamps := make([]migrationFile, 0, len(versions))
	for _, version := range versions {
		migration, ok := byVersion[version]
		if !ok {
			return fmt.Errorf("baseline version %s is missing from incremental migrations", version)
		}
		stamps = append(stamps, migration)
	}

	log.Printf("Empty database detected; applying current schema baseline (%d stamped versions)", len(stamps))

	tx := db.Begin()
	if tx.Error != nil {
		return fmt.Errorf("begin schema baseline failed: %w", tx.Error)
	}

	if err := applySQLScript(tx, currentSchemaSQLFile, string(schemaSQL)); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Exec("SET search_path TO public").Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("reset search_path after schema baseline failed: %w", err)
	}
	if err := applySQLScript(tx, currentSchemaSeedFile, string(seedSQL)); err != nil {
		tx.Rollback()
		return err
	}

	appliedAt := time.Now()
	for _, migration := range stamps {
		record := SchemaMigration{
			Version:   migration.Version,
			Name:      migration.Name,
			Checksum:  migration.Checksum,
			AppliedAt: appliedAt,
		}
		if err := tx.Create(&record).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("stamp baseline version %s failed: %w", migration.Version, err)
		}
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("commit schema baseline failed: %w", err)
	}
	return nil
}

func applySQLScript(db *gorm.DB, name, sql string) error {
	for _, stmt := range splitSQLStatements(sql) {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("apply %s failed: %w", name, err)
		}
	}
	return nil
}

func ensureSchemaMigrationsTable(db *gorm.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`
	if err := db.Exec(ddl).Error; err != nil {
		return fmt.Errorf("create schema_migrations failed: %w", err)
	}
	return nil
}

func loadMigrations() ([]migrationFile, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations failed: %w", err)
	}

	files := make([]migrationFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		version, name, err := parseMigrationFileName(entry.Name())
		if err != nil {
			return nil, err
		}

		path := "migrations/" + entry.Name()
		content, err := migrationFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read migration %s failed: %w", entry.Name(), err)
		}

		sql := strings.TrimSpace(string(content))
		sum := sha256.Sum256(content)
		files = append(files, migrationFile{
			Version:  version,
			Name:     name,
			Path:     path,
			Checksum: hex.EncodeToString(sum[:]),
			SQL:      sql,
		})
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].Version == files[j].Version {
			return files[i].Name < files[j].Name
		}
		return files[i].Version < files[j].Version
	})

	return files, nil
}

func parseMigrationFileName(name string) (string, string, error) {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	parts := strings.SplitN(base, "_", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("invalid migration filename: %s", name)
	}
	return parts[0], parts[1], nil
}

func loadAppliedMigrations(db *gorm.DB) (map[string]SchemaMigration, error) {
	var rows []SchemaMigration
	if err := db.Order("version ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("load applied migrations failed: %w", err)
	}

	out := make(map[string]SchemaMigration, len(rows))
	for _, row := range rows {
		out[row.Version] = row
	}
	return out, nil
}

func applyMigrationFile(db *gorm.DB, migration migrationFile) error {
	tx := db.Begin()
	if tx.Error != nil {
		return fmt.Errorf("begin migration %s failed: %w", migration.Path, tx.Error)
	}

	for _, stmt := range splitSQLStatements(migration.SQL) {
		if err := tx.Exec(stmt).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s failed: %w", migration.Path, err)
		}
	}

	record := SchemaMigration{
		Version:   migration.Version,
		Name:      migration.Name,
		Checksum:  migration.Checksum,
		AppliedAt: time.Now(),
	}
	if err := tx.Create(&record).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("record migration %s failed: %w", migration.Path, err)
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("commit migration %s failed: %w", migration.Path, err)
	}

	return nil
}

// splitSQLStatements splits SQL text on top-level semicolons, correctly
// handling $$ dollar-quoted blocks (PL/pgSQL DO blocks, function bodies)
// and single-quoted string literals that may contain semicolons.
func splitSQLStatements(sql string) []string {
	var stmts []string
	var current strings.Builder
	inSingleQuote := false
	dollarTag := "" // active dollar-quote tag (e.g. "$$" or "$func$")
	inDollarQuote := false

	runes := []rune(sql)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]

		// Handle single-quoted strings (skip escaped quotes '')
		if ch == '\'' && !inDollarQuote {
			inSingleQuote = !inSingleQuote
			current.WriteRune(ch)
			continue
		}
		if inSingleQuote {
			current.WriteRune(ch)
			continue
		}

		if ch == '-' && i+1 < len(runes) && runes[i+1] == '-' {
			i++
			for i+1 < len(runes) && runes[i+1] != '\n' {
				i++
			}
			continue
		}

		// Handle dollar-quoting: $$ or $tag$
		if ch == '$' {
			tag := extractDollarTag(runes, i)
			if tag != "" {
				if inDollarQuote && tag == dollarTag {
					// Closing dollar quote
					current.WriteString(tag)
					i += len([]rune(tag)) - 1
					inDollarQuote = false
					dollarTag = ""
					continue
				} else if !inDollarQuote {
					// Opening dollar quote
					current.WriteString(tag)
					i += len([]rune(tag)) - 1
					inDollarQuote = true
					dollarTag = tag
					continue
				}
			}
		}
		if inDollarQuote {
			current.WriteRune(ch)
			continue
		}

		// Top-level semicolon: split point
		if ch == ';' {
			stmt := strings.TrimSpace(current.String())
			if stmt != "" {
				stmts = append(stmts, stmt)
			}
			current.Reset()
			continue
		}

		current.WriteRune(ch)
	}

	// Trailing statement without semicolon
	if stmt := strings.TrimSpace(current.String()); stmt != "" {
		stmts = append(stmts, stmt)
	}

	return stmts
}

// extractDollarTag tries to extract a dollar-quoted tag starting at position i.
// Returns the full tag (e.g. "$$" or "$func$") or empty string if not a valid tag.
func extractDollarTag(runes []rune, i int) string {
	if i >= len(runes) || runes[i] != '$' {
		return ""
	}
	// Look for closing $
	for j := i + 1; j < len(runes); j++ {
		if runes[j] == '$' {
			return string(runes[i : j+1])
		}
		// Dollar-quote tags can only contain letters, digits, and underscores
		if !isTagChar(runes[j]) {
			return ""
		}
	}
	return ""
}

func isTagChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') || r == '_'
}

// verifyMigrations checks that all embedded migrations have been applied
// and that their checksums match the recorded values.
func verifyMigrations(db *gorm.DB) error {
	if err := ensureSchemaMigrationsTable(db); err != nil {
		return err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	applied, err := loadAppliedMigrations(db)
	if err != nil {
		return err
	}

	var errs []string
	for _, m := range migrations {
		prev, ok := applied[m.Version]
		if !ok {
			errs = append(errs, fmt.Sprintf("migration %s (%s) has not been applied", m.Version, m.Name))
			continue
		}
		if prev.Checksum != m.Checksum {
			errs = append(errs, fmt.Sprintf(
				"migration %s (%s) checksum mismatch: db=%s code=%s",
				m.Version, m.Name, prev.Checksum, m.Checksum,
			))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("migration verification failed:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

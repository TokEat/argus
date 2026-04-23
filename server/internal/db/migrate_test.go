package db

import "testing"

func TestParseMigrationMode(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    MigrationMode
		wantErr bool
	}{
		{name: "empty defaults to apply", raw: "", want: MigrationModeApply},
		{name: "apply", raw: "apply", want: MigrationModeApply},
		{name: "verify", raw: "verify", want: MigrationModeVerify},
		{name: "dev-auto", raw: "dev-auto", want: MigrationModeDevAuto},
		{name: "invalid", raw: "sqlite", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMigrationMode(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestLoadMigrations(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations returned error: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatalf("expected embedded migrations, got none")
	}

	prev := ""
	for _, migration := range migrations {
		if migration.Version == "" || migration.Name == "" {
			t.Fatalf("invalid migration metadata: %+v", migration)
		}
		if migration.Checksum == "" {
			t.Fatalf("migration checksum missing for %s", migration.Path)
		}
		if prev != "" && migration.Version < prev {
			t.Fatalf("migrations out of order: %s before %s", prev, migration.Version)
		}
		prev = migration.Version
	}
}

func TestSplitSQLStatements(t *testing.T) {
	sql := `
CREATE TABLE foo (id INT);

ALTER TABLE foo ADD COLUMN name TEXT;
`
	stmts := splitSQLStatements(sql)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
}

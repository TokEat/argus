package localstate

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTSVRowRoundTrip(t *testing.T) {
	want := []string{"", "plain", "tab\tvalue", "line\nvalue", "carriage\rreturn", `slash\value`, "中文", "=SUM(1,1)", "+formula", "-formula", "@formula"}
	encoded := encodeTSVRow(want...)
	if strings.Count(encoded, "\n") != 1 {
		t.Fatalf("encoded row must occupy exactly one physical line: %q", encoded)
	}
	got, err := decodeTSVRow(encoded)
	if err != nil {
		t.Fatalf("decode row: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded row = %#v, want %#v", got, want)
	}
}

func TestTSVRowNeutralizesSpreadsheetFormulas(t *testing.T) {
	encoded := encodeTSVRow("=SUM(1,1)", "+cmd", "-1+2", "@payload")
	for _, field := range strings.Split(strings.TrimSuffix(encoded, "\n"), "\t") {
		if strings.HasPrefix(field, "=") || strings.HasPrefix(field, "+") || strings.HasPrefix(field, "-") || strings.HasPrefix(field, "@") {
			t.Fatalf("formula-like field was not neutralized: %q", field)
		}
	}
}

func TestDecodeTSVRowRejectsDamagedEscapes(t *testing.T) {
	for _, input := range []string{`bad\q`, `unfinished\`} {
		if _, err := decodeTSVRow(input); err == nil {
			t.Fatalf("decodeTSVRow(%q) unexpectedly succeeded", input)
		}
	}
}

func TestEnsureLayoutCreatesAndValidatesStateTables(t *testing.T) {
	home := Home{Root: filepath.Join(t.TempDir(), "argus-data")}
	layout, err := EnsureLayout(home)
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	for path, schema := range map[string]tableSchema{
		layout.AssetsPath:   assetsSchema,
		layout.CoveragePath: coverageSchema,
	} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if got, want := string(contents), tableHeader(schema); got != want {
			t.Fatalf("%s contents = %q, want %q", path, got, want)
		}
	}
	if _, err := EnsureLayout(home); err != nil {
		t.Fatalf("idempotent ensure layout: %v", err)
	}

	damaged := []byte("# argus-tsv/v0\tassets\nwrong\theader\n")
	if err := os.WriteFile(layout.AssetsPath, damaged, 0o600); err != nil {
		t.Fatalf("damage assets table: %v", err)
	}
	if _, err := EnsureLayout(home); err == nil || !strings.Contains(err.Error(), "unsupported or damaged") {
		t.Fatalf("damaged header error = %v", err)
	}
	contents, err := os.ReadFile(layout.AssetsPath)
	if err != nil {
		t.Fatalf("read damaged assets table: %v", err)
	}
	if !reflect.DeepEqual(contents, damaged) {
		t.Fatal("damaged state table was unexpectedly overwritten")
	}
}

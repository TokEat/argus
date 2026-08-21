package common

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestParseAppendListReadsFileOrTokens(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "extra.txt")
	if err := os.WriteFile(file, []byte("alpha\n\nbeta\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := parseAppendList(file)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromFile, []string{"alpha", "beta"}) {
		t.Fatalf("file list = %#v", fromFile)
	}
	fromTokens, err := parseAppendList("123456 admin@123")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromTokens, []string{"123456", "admin@123"}) {
		t.Fatalf("token list = %#v", fromTokens)
	}
}

func TestValidateCLIRiskFlagsRejectsAppendWithDisableOrReplace(t *testing.T) {
	passwordAppendRaw = "123456"
	t.Cleanup(func() { passwordAppendRaw = "" })
	if err := validateCLIRiskFlags(structs.Config{NoBrute: true}); err == nil {
		t.Fatal("expected -pwda vs -nobr conflict")
	}
	if err := validateCLIRiskFlags(structs.Config{Password: "admin : 123"}); err == nil {
		t.Fatal("expected -pwda vs -up conflict")
	}
}

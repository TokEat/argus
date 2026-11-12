package localstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveHomeDefaultsBesideExecutable(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "portable")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	executable := filepath.Join(binDir, "argus.exe")
	if err := os.WriteFile(executable, []byte("test"), 0o755); err != nil {
		t.Fatalf("write executable placeholder: %v", err)
	}

	got, err := resolveHome(executable, "", root)
	if err != nil {
		t.Fatalf("resolve default home: %v", err)
	}
	want := filepath.Join(binDir, DefaultHomeName)
	if resolvedBinDir, err := filepath.EvalSymlinks(binDir); err == nil {
		want = filepath.Join(resolvedBinDir, DefaultHomeName)
	}
	if got != want {
		t.Fatalf("default home = %q, want %q", got, want)
	}
}

func TestResolveHomeHonorsAbsoluteAndRelativeOverride(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "bin", "argus")

	absolute := filepath.Join(root, "external-state")
	got, err := resolveHome(executable, "  "+absolute+"  ", root)
	if err != nil {
		t.Fatalf("resolve absolute override: %v", err)
	}
	if got != absolute {
		t.Fatalf("absolute override = %q, want %q", got, absolute)
	}

	got, err = resolveHome(executable, filepath.Join("portable", "state"), root)
	if err != nil {
		t.Fatalf("resolve relative override: %v", err)
	}
	want := filepath.Join(root, "portable", "state")
	if got != want {
		t.Fatalf("relative override = %q, want %q", got, want)
	}
}

func TestResolveHomeRejectsMissingBasePaths(t *testing.T) {
	if _, err := resolveHome("argus", "", ""); err == nil {
		t.Fatal("empty working directory was accepted")
	}
	if _, err := resolveHome("", "", t.TempDir()); err == nil {
		t.Fatal("empty executable path was accepted")
	}
}

func TestResolveHomeDoesNotNeedWorkingDirectoryForAbsolutePaths(t *testing.T) {
	root := t.TempDir()
	absoluteOverride := filepath.Join(root, "override")
	if got, err := resolveHome("", absoluteOverride, ""); err != nil || got != absoluteOverride {
		t.Fatalf("absolute override with unavailable cwd = %q, %v", got, err)
	}
	absoluteExecutable := filepath.Join(root, "bin", "argus")
	want := filepath.Join(filepath.Dir(absoluteExecutable), DefaultHomeName)
	if got, err := resolveHome(absoluteExecutable, "", ""); err != nil || got != want {
		t.Fatalf("absolute executable with unavailable cwd = %q, %v, want %q", got, err, want)
	}
}

func TestEnsureCreatesPrivateDirectoryAtOverride(t *testing.T) {
	root := filepath.Join(t.TempDir(), "argus-home")
	t.Setenv(HomeEnvironment, root)

	home, err := Ensure()
	if err != nil {
		t.Fatalf("ensure home: %v", err)
	}
	if home.Root != root {
		t.Fatalf("ensured root = %q, want %q", home.Root, root)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat ensured root: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("ensured root is not a directory: %v", info.Mode())
	}
	if err := os.WriteFile(filepath.Join(root, "preserved.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatalf("seed existing data: %v", err)
	}
	if _, err := Ensure(); err != nil {
		t.Fatalf("ensure existing home: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "preserved.txt")); err != nil || string(data) != "keep" {
		t.Fatalf("existing data was not preserved: data=%q err=%v", data, err)
	}
}

func TestEnsureRejectsFileOverride(t *testing.T) {
	root := filepath.Join(t.TempDir(), "argus-home")
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("seed file override: %v", err)
	}
	t.Setenv(HomeEnvironment, root)
	if _, err := Ensure(); err == nil {
		t.Fatal("file override was accepted as a data directory")
	}
}

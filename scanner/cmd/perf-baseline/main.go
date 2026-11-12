// perf-baseline records target-free process-wall timing samples as versioned JSON.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/TokEat/argus/scanner/internal/arsenal"
	"github.com/TokEat/argus/scanner/internal/engine"
	"github.com/TokEat/argus/scanner/structs"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type report struct {
	SchemaVersion string    `json:"schema_version"`
	Mode          string    `json:"mode"`
	Case          string    `json:"case"`
	CapturedAt    time.Time `json:"captured_at"`
	Warmups       int       `json:"warmups"`
	Samples       int       `json:"samples"`
	MinNS         int64     `json:"min_ns"`
	P50NS         int64     `json:"p50_ns"`
	P95NS         int64     `json:"p95_ns"`
	MaxNS         int64     `json:"max_ns"`
	BinarySHA256  string    `json:"binary_sha256"`
	ArsenalSHA256 string    `json:"arsenal_sha256"`
	ConfigSHA256  string    `json:"config_sha256"`
	GoVersion     string    `json:"go_version"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
}

type commandArgList []string

func (values *commandArgList) String() string { return fmt.Sprintf("%d argument(s)", len(*values)) }
func (values *commandArgList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	mode := flag.String("mode", "process", "benchmark mode: process or agent-context")
	caseName := flag.String("case", "", "stable benchmark case name")
	warmups := flag.Int("warmups", 1, "warmup runs")
	samples := flag.Int("samples", 10, "measured runs")
	binary := flag.String("binary", "", "binary to execute")
	agentConfigDir := flag.String("agent-config-dir", "", "materialized Agent rule config directory")
	argsJSON := flag.String("args-json", "[]", "JSON string array passed to the process (never emitted)")
	var repeatedArgs commandArgList
	flag.Var(&repeatedArgs, "arg", "single process argument; repeat as needed (never emitted)")
	arsenalFile := flag.String("arsenal-file", "", "optional Arsenal file hashed into the report")
	configFile := flag.String("config-file", "", "optional config file hashed into the report")
	runTimeout := flag.Duration("timeout", 2*time.Minute, "maximum duration of each process run")
	flag.Parse()
	if strings.TrimSpace(*caseName) != *caseName || *caseName == "" || len(*caseName) > 128 || (*mode != "process" && *mode != "agent-context") || (*mode == "process" && *binary == "") || (*mode == "agent-context" && (*agentConfigDir == "" || *arsenalFile == "")) || *samples < 1 || *samples > 1000 || *warmups < 0 || *warmups > 100 || *runTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "valid mode, case, inputs, and positive samples are required")
		os.Exit(2)
	}
	commandArgs, err := parseCommandArgs(*argsJSON)
	if err != nil {
		fmt.Fprintln(os.Stderr, "args-json must be a bounded JSON string array")
		os.Exit(2)
	}
	if len(repeatedArgs) > 0 {
		if *argsJSON != "[]" {
			fmt.Fprintln(os.Stderr, "use either args-json or repeated arg flags")
			os.Exit(2)
		}
		commandArgs = append([]string(nil), repeatedArgs...)
		if err := validateCommandArgs(commandArgs); err != nil {
			fmt.Fprintln(os.Stderr, "process arguments are not bounded")
			os.Exit(2)
		}
	}
	if *mode == "agent-context" && len(commandArgs) != 0 {
		fmt.Fprintln(os.Stderr, "agent-context mode does not accept process arguments")
		os.Exit(2)
	}
	runProcess := func() time.Duration {
		ctx, cancel := context.WithTimeout(context.Background(), *runTimeout)
		defer cancel()
		start := time.Now()
		cmd := exec.CommandContext(ctx, *binary, commandArgs...)
		cmd.Stdout, cmd.Stderr = nil, nil
		if err := cmd.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "benchmark command failed")
			os.Exit(1)
		}
		return time.Since(start)
	}
	run := runProcess
	verifiedArsenalHash := ""
	if *mode == "agent-context" {
		cfg, err := agentContextConfig(*agentConfigDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Agent config directory is incomplete")
			os.Exit(1)
		}
		verifiedArsenalHash, err = verifyAgentContextArsenal(cfg, *arsenalFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Agent Arsenal identity does not match the materialized manifest")
			os.Exit(1)
		}
		run = func() time.Duration {
			start := time.Now()
			ctx, err := engine.NewScanContext(cfg)
			duration := time.Since(start)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Agent context benchmark failed")
				os.Exit(1)
			}
			ctx.Close()
			return duration
		}
	}
	for i := 0; i < *warmups; i++ {
		run()
	}
	values := make([]int64, 0, *samples)
	for i := 0; i < *samples; i++ {
		values = append(values, int64(run()))
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	binaryPath := *binary
	if *mode == "agent-context" {
		binaryPath, err = os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "resolve baseline executable failed")
			os.Exit(1)
		}
	}
	binaryHash, err := fileSHA256(binaryPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash binary failed")
		os.Exit(1)
	}
	arsenalHash := verifiedArsenalHash
	if *mode != "agent-context" {
		arsenalHash, err = optionalFileSHA256(*arsenalFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hash Arsenal identity failed")
			os.Exit(1)
		}
	}
	configHash, err := optionalFileSHA256(*configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash config identity failed")
		os.Exit(1)
	}
	r := report{
		SchemaVersion: "argus.performance-baseline/v1", Mode: *mode, Case: *caseName, CapturedAt: time.Now().UTC(), Warmups: *warmups, Samples: *samples,
		MinNS: values[0], P50NS: nearest(values, 50), P95NS: nearest(values, 95), MaxNS: values[len(values)-1],
		BinarySHA256: binaryHash, ArsenalSHA256: arsenalHash, ConfigSHA256: configHash,
		GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}

func agentContextConfig(configDir string) (engine.Config, error) {
	absolute, err := filepath.Abs(filepath.Clean(configDir))
	if err != nil {
		return engine.Config{}, err
	}
	manifest, err := readAgentContextManifest(absolute)
	if err != nil {
		return engine.Config{}, err
	}
	paths := []string{filepath.Join(absolute, "finger.yaml"), filepath.Join(absolute, "workflow.yaml"), filepath.Join(absolute, "dir.yaml")}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return engine.Config{}, fmt.Errorf("required rule file is unavailable")
		}
	}
	for _, directory := range []string{filepath.Join(absolute, "pocs"), filepath.Join(absolute, "active-fingerprints")} {
		info, statErr := os.Stat(directory)
		if statErr != nil || !info.IsDir() {
			return engine.Config{}, fmt.Errorf("required rule directory is unavailable")
		}
	}
	cfg := engine.Config(structs.DefaultConfig())
	cfg.RuleFilesOnly = true
	cfg.NoPoc = true
	cfg.GolangPoc = false
	cfg.DisableGeneralPoc = true
	cfg.FingerConfigFilePath = paths[0]
	cfg.WorkflowYamlPath = paths[1]
	cfg.DirSearchYaml = paths[2]
	cfg.ActiveFingerprintTemplate = filepath.Join(absolute, "active-fingerprints")
	cfg.NucleiTemplate = filepath.Join(absolute, "pocs")
	cfg.Targets = nil
	cfg.KnowledgePackageHash = manifest.PackageSHA256
	cfg.KnowledgeRuleVersion = manifest.RuleVersion
	return cfg, nil
}

func verifyAgentContextArsenal(cfg engine.Config, arsenalFile string) (string, error) {
	actual, err := fileSHA256(arsenalFile)
	if err != nil {
		return "", err
	}
	if actual != cfg.KnowledgePackageHash {
		return "", fmt.Errorf("Arsenal SHA-256 does not match the materialized manifest")
	}
	return actual, nil
}

func readAgentContextManifest(configDir string) (arsenal.RulePackageManifest, error) {
	manifestPath := filepath.Join(configDir, ".argus-arsenal.json")
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return arsenal.RulePackageManifest{}, fmt.Errorf("read Agent rule manifest: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 1<<20 {
		return arsenal.RulePackageManifest{}, fmt.Errorf("Agent rule manifest must be a bounded regular file")
	}
	file, err := os.Open(manifestPath)
	if err != nil {
		return arsenal.RulePackageManifest{}, fmt.Errorf("open Agent rule manifest: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var manifest arsenal.RulePackageManifest
	if err := decoder.Decode(&manifest); err != nil {
		return arsenal.RulePackageManifest{}, fmt.Errorf("decode Agent rule manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return arsenal.RulePackageManifest{}, fmt.Errorf("Agent rule manifest contains trailing data")
	}
	if manifest.SchemaVersion != arsenal.RulePackageSchemaVersion {
		return arsenal.RulePackageManifest{}, fmt.Errorf("unsupported Agent rule manifest schema")
	}
	if !isManifestIdentity(manifest.Hash) || !isManifestIdentity(manifest.RuleVersion) || !isLowercaseSHA256(manifest.PackageSHA256) {
		return arsenal.RulePackageManifest{}, fmt.Errorf("invalid Agent rule manifest identity")
	}
	return manifest, nil
}

func isManifestIdentity(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func isLowercaseSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func parseCommandArgs(raw string) ([]string, error) {
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	var args []string
	if err := decoder.Decode(&args); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || args == nil {
		return nil, fmt.Errorf("invalid trailing data or argument count")
	}
	if err := validateCommandArgs(args); err != nil {
		return nil, err
	}
	return args, nil
}

func validateCommandArgs(args []string) error {
	if len(args) > 32 {
		return fmt.Errorf("too many process arguments")
	}
	for _, arg := range args {
		if len(arg) > 4096 || strings.ContainsAny(arg, "\r\n\x00") {
			return fmt.Errorf("invalid process argument")
		}
	}
	return nil
}

func optionalFileSHA256(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "_not_supplied", nil
	}
	return fileSHA256(path)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func nearest(v []int64, p int) int64 { i := (p*len(v)+99)/100 - 1; return v[i] }

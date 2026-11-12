package common

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/TokEat/argus/scanner/gopocs"
	"github.com/TokEat/argus/scanner/structs"
)

func hasHTMLReportExtension(name string) bool {
	suffix := filepath.Ext(name)
	return strings.EqualFold(suffix, ".html") || strings.EqualFold(suffix, ".htm")
}

func validateCLIRiskFlags(config structs.Config) error {
	if config.NoPoc && strings.TrimSpace(config.PocNameForSearch) != "" {
		return &CLIUsageError{Message: "-nopoc 不能与 -poc/--poc-name 同时使用"}
	}
	hasAppend := len(config.UserAppend) > 0 || len(config.PasswordAppend) > 0 || strings.TrimSpace(passwordAppendRaw) != "" || strings.TrimSpace(userAppendRaw) != ""
	if hasAppend && (strings.TrimSpace(config.Password) != "" || strings.TrimSpace(config.PasswordFile) != "") {
		return &CLIUsageError{Message: "-pwda/-usea 不能与 -up/--username-password 或 -upf 同时使用"}
	}
	if hasAppend && (config.NoBrute || config.NoGoPoc) {
		return &CLIUsageError{Message: "-pwda/-usea 不能与 -nobr 或 -nogpoc 同时使用"}
	}
	if err := gopocs.ValidateModuleFilter(config.GoPocModules); err != nil {
		return &CLIUsageError{Message: err.Error()}
	}
	return nil
}

func applyCLIAppendDictionaries() error {
	passwords, err := parseAppendList(passwordAppendRaw)
	if err != nil {
		return err
	}
	users, err := parseAppendList(userAppendRaw)
	if err != nil {
		return err
	}
	structs.GlobalConfig.PasswordAppend = passwords
	structs.GlobalConfig.UserAppend = users
	return validateCLIRiskFlags(structs.GlobalConfig)
}

func sanitizeResultDirectoryName(value string) string {
	var sanitized strings.Builder
	for _, character := range value {
		switch {
		case unicode.IsLetter(character), unicode.IsNumber(character), character == '-', character == '_', character == '.':
			sanitized.WriteRune(character)
		default:
			sanitized.WriteByte('_')
		}
		if sanitized.Len() >= 80 {
			break
		}
	}
	result := strings.Trim(sanitized.String(), "._")
	if result == "" {
		return "task"
	}
	return result
}

func validateCLIArtifactNames(outputName, reportName, auditName string) error {
	type artifact struct {
		label string
		name  string
	}
	artifacts := []artifact{{label: "结果文件", name: outputName}, {label: "HTML 报告", name: reportName}}
	if auditName != "" {
		artifacts = append(artifacts, artifact{label: "审计日志", name: auditName})
	}
	for left := 0; left < len(artifacts); left++ {
		for right := left + 1; right < len(artifacts); right++ {
			if portableArtifactNameKey(artifacts[left].name) == portableArtifactNameKey(artifacts[right].name) {
				return &CLIUsageError{Message: fmt.Sprintf("%s与%s不能使用同一文件名", artifacts[left].label, artifacts[right].label)}
			}
		}
	}
	return nil
}

func portableArtifactNameKey(name string) string {
	// Win32 aliases names that differ only by case or trailing dots/spaces.
	// Apply that stricter comparison on every platform so a CLI invocation is
	// portable and cannot merge result, report, and audit sinks on Windows.
	return strings.ToLower(strings.TrimRight(filepath.Clean(name), ". "))
}

func createUniqueResultDirectory(root, base string) (string, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	for suffix := 0; suffix < 10_000; suffix++ {
		name := base
		if suffix > 0 {
			name = fmt.Sprintf("%s_%d", base, suffix+1)
		}
		candidate := filepath.Join(root, name)
		if err := os.Mkdir(candidate, 0o755); err == nil {
			return candidate, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("too many result directory collisions")
}

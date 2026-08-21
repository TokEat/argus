package common

import (
	"fmt"
	"os"
	"strings"

	"github.com/P0lar1ght/argus/scanner/utils"
)

func parseAppendList(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	info, err := os.Stat(raw)
	if err == nil {
		if !info.Mode().IsRegular() {
			return nil, &CLIUsageError{Message: fmt.Sprintf("追加字典路径不是普通文件: %s", raw)}
		}
		data, readErr := os.ReadFile(raw)
		if readErr != nil {
			return nil, fmt.Errorf("read append dictionary: %w", readErr)
		}
		return splitAppendLines(string(data)), nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat append dictionary: %w", err)
	}
	return splitAppendTokens(raw), nil
}

func splitAppendLines(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	var values []string
	for _, line := range strings.Split(content, "\n") {
		if value := strings.TrimSpace(line); value != "" {
			values = append(values, value)
		}
	}
	return utils.RemoveDuplicateElement(values)
}

func splitAppendTokens(raw string) []string {
	return utils.RemoveDuplicateElement(strings.Fields(raw))
}

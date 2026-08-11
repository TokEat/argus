package localstate

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const TSVSchemaVersion = "argus-tsv/v1"

type tableSchema struct {
	Name    string
	Columns []string
}

var (
	assetsSchema = tableSchema{Name: "assets", Columns: []string{
		"asset_key", "normalized_target", "asset_type", "network_zone", "first_seen", "last_seen", "last_run_id", "status", "content_hash",
	}}
	coverageSchema = tableSchema{Name: "coverage", Columns: []string{
		"work_key", "normalized_target", "stage", "scope_hash", "config_hash", "rule_version", "outcome", "content_hash", "observed_at", "valid_until", "last_run_id",
	}}
	targetsSchema = tableSchema{Name: "run_targets", Columns: []string{
		"target_index", "raw_target", "normalized_target", "target_type", "action", "reason",
	}}
	findingsSchema = tableSchema{Name: "run_findings", Columns: []string{
		"sequence", "observed_at", "type", "target", "ip", "port", "protocol", "uri", "domain", "fingerprints_json", "web_status", "web_title", "poc_name", "severity", "description", "nuclei_json", "additional", "display",
	}}
	runCoverageSchema = tableSchema{Name: "run_coverage", Columns: append([]string{"action", "reason"}, coverageSchema.Columns...)}
	timingSchema      = tableSchema{Name: "timing", Columns: []string{
		"event_id", "attempt_id", "agent_id", "kind", "stage", "outcome", "started_at", "finished_at", "duration_ns",
	}}
)

func encodeTSVRow(fields ...string) string {
	encoded := make([]string, len(fields))
	for index, field := range fields {
		encoded[index] = escapeTSVField(field)
	}
	return strings.Join(encoded, "\t") + "\n"
}

func escapeTSVField(value string) string {
	var builder strings.Builder
	for index, char := range value {
		if index == 0 && (char == '=' || char == '+' || char == '-' || char == '@') {
			// Keep spreadsheet viewers from interpreting attacker-controlled
			// findings as formulas while preserving a reversible text format.
			builder.WriteRune('\\')
			builder.WriteRune(char)
			continue
		}
		switch char {
		case '\\':
			builder.WriteString(`\\`)
		case '\t':
			builder.WriteString(`\t`)
		case '\r':
			builder.WriteString(`\r`)
		case '\n':
			builder.WriteString(`\n`)
		default:
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

func decodeTSVRow(line string) ([]string, error) {
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	fields := []string{}
	var field strings.Builder
	escaped := false
	for _, char := range line {
		if escaped {
			switch char {
			case '\\', '=', '+', '-', '@':
				field.WriteRune(char)
			case 't':
				field.WriteRune('\t')
			case 'r':
				field.WriteRune('\r')
			case 'n':
				field.WriteRune('\n')
			default:
				return nil, fmt.Errorf("invalid TSV escape \\%c", char)
			}
			escaped = false
			continue
		}
		switch char {
		case '\\':
			escaped = true
		case '\t':
			fields = append(fields, field.String())
			field.Reset()
		default:
			field.WriteRune(char)
		}
	}
	if escaped {
		return nil, errors.New("unterminated TSV escape")
	}
	fields = append(fields, field.String())
	return fields, nil
}

func tableHeader(schema tableSchema) string {
	return encodeTSVRow("# "+TSVSchemaVersion, schema.Name) + encodeTSVRow(schema.Columns...)
}

func ensureTable(path string, schema tableSchema) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, writeErr := io.WriteString(file, tableHeader(schema)); writeErr != nil {
			_ = file.Close()
			return fmt.Errorf("write %s table header: %w", schema.Name, writeErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("close %s table: %w", schema.Name, closeErr)
		}
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create %s table: %w", schema.Name, err)
	}
	return validateTableHeader(path, schema)
}

func validateTableHeader(path string, schema tableSchema) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s table: %w", schema.Name, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	lines := make([]string, 0, 2)
	for scanner.Scan() && len(lines) < 2 {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s table header: %w", schema.Name, err)
	}
	want := strings.Split(strings.TrimSuffix(tableHeader(schema), "\n"), "\n")
	if len(lines) != 2 || lines[0] != want[0] || lines[1] != want[1] {
		return fmt.Errorf("%s has an unsupported or damaged TSV header", filepath.Base(path))
	}
	return nil
}

func createRunTable(path string, schema tableSchema) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if _, err := io.WriteString(file, tableHeader(schema)); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write %s header: %w", filepath.Base(path), err)
	}
	return file, nil
}

func readTable(path string, schema tableSchema) ([][]string, []string, error) {
	if err := validateTableHeader(path, schema); err != nil {
		return nil, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s table: %w", schema.Name, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	rows := [][]string{}
	warnings := []string{}
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if lineNumber <= 2 || strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		row, decodeErr := decodeTSVRow(scanner.Text())
		if decodeErr != nil {
			warnings = append(warnings, fmt.Sprintf("%s line %d skipped: %v", filepath.Base(path), lineNumber, decodeErr))
			continue
		}
		if len(row) != len(schema.Columns) {
			warnings = append(warnings, fmt.Sprintf(
				"%s line %d skipped: got %d columns, want %d",
				filepath.Base(path), lineNumber, len(row), len(schema.Columns),
			))
			continue
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, warnings, fmt.Errorf("read %s table: %w", schema.Name, err)
	}
	return rows, warnings, nil
}

func writeTableAtomic(path string, schema tableSchema, rows [][]string) error {
	var builder strings.Builder
	builder.WriteString(tableHeader(schema))
	for rowNumber, row := range rows {
		if len(row) != len(schema.Columns) {
			return fmt.Errorf("write %s row %d: got %d columns, want %d", schema.Name, rowNumber+1, len(row), len(schema.Columns))
		}
		builder.WriteString(encodeTSVRow(row...))
	}
	return writeFileAtomic(path, []byte(builder.String()), 0o600)
}

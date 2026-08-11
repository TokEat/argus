// Package ddout provides the scanner output boundary.
//
// CLI text output remains human readable. CLI JSON output is UTF-8 NDJSON:
// each line is an independently decodable, versioned record. Agent callers
// continue to use SetOutputSink and receive the original OutputMessage.
package ddout

import (
	"dddd/scanner/structs"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

const JSONSchemaVersion = "argus.cli-output/v1"

type WebInfo = structs.WebInfo
type OutputMessage = structs.OutputMessage
type GoPocsResultType = structs.GoPocsResultType

var OutputType = "text"
var OutputFileName string

// RunCounts is the stable, bounded counter set in a terminal summary.
type RunCounts struct {
	Targets            int64 `json:"targets"`
	Findings           int64 `json:"findings"`
	Coverage           int64 `json:"coverage"`
	AssetsNew          int64 `json:"assets_new"`
	ServicesChanged    int64 `json:"services_changed"`
	AssetsDisappeared  int64 `json:"assets_disappeared"`
	AssetsNotAssessed  int64 `json:"assets_not_assessed"`
	StagesExecuted     int64 `json:"stages_executed"`
	StagesReused       int64 `json:"stages_reused"`
	TargetsFull        int64 `json:"targets_full"`
	TargetsIncremental int64 `json:"targets_incremental"`
}

// RunSummary is emitted once by EndRun in JSON mode. Findings always reflects
// records successfully written through this CLI output stream.
type RunSummary struct {
	Status   string    `json:"status"`
	ExitCode int       `json:"exit_code"`
	Counts   RunCounts `json:"counts"`
}

// JSONFinding is the stable CLI projection of a scanner finding. Pointer
// fields prevent empty Web/GoPoc structs from appearing in every record.
type JSONFinding struct {
	Type          string     `json:"type,omitempty"`
	IP            string     `json:"ip,omitempty"`
	IPs           []string   `json:"ips,omitempty"`
	Port          string     `json:"port,omitempty"`
	Protocol      string     `json:"protocol,omitempty"`
	Web           *JSONWeb   `json:"web,omitempty"`
	Finger        []string   `json:"finger,omitempty"`
	Domain        string     `json:"domain,omitempty"`
	GoPoc         *JSONGoPoc `json:"go_poc,omitempty"`
	URI           string     `json:"uri,omitempty"`
	City          string     `json:"city,omitempty"`
	AdditionalMsg string     `json:"am,omitempty"`
	Nuclei        string     `json:"nuclei,omitempty"`
}

type JSONWeb struct {
	Status string `json:"status,omitempty"`
	Title  string `json:"title,omitempty"`
}

type JSONGoPoc struct {
	PocName     string `json:"poc_name,omitempty"`
	Security    string `json:"security,omitempty"`
	Description string `json:"description,omitempty"`
	Target      string `json:"target,omitempty"`
	InfoLeft    string `json:"info_left,omitempty"`
	InfoRight   string `json:"info_right,omitempty"`
	ShowMsg     string `json:"show_msg,omitempty"`
}

// JSONRecord is the stable NDJSON wire record used by the CLI only.
// Exactly one of Finding or Summary is set according to RecordType.
type JSONRecord struct {
	SchemaVersion string       `json:"schema_version"`
	RecordType    string       `json:"record_type"`
	Sequence      uint64       `json:"sequence"`
	RunID         string       `json:"run_id,omitempty"`
	Finding       *JSONFinding `json:"finding,omitempty"`
	Summary       *RunSummary  `json:"summary,omitempty"`
}

var (
	outputSink func(msg OutputMessage)
	sinkMu     sync.Mutex

	writeMu      sync.Mutex
	stdout       io.Writer = os.Stdout
	runID        string
	sequence     uint64
	findingCount int64
	runStarted   bool
	runEnded     bool
	runWriteErr  error
)

// SetOutputSink sets a non-CLI output sink and returns the prior sink.
func SetOutputSink(sink func(msg OutputMessage)) func(msg OutputMessage) {
	sinkMu.Lock()
	defer sinkMu.Unlock()
	prev := outputSink
	outputSink = sink
	return prev
}

// BeginRun starts one CLI output run. It does not emit a record; EndRun emits
// the single terminal run_summary record in JSON mode.
func BeginRun(id string) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	if runStarted && !runEnded {
		return errors.New("ddout: run already started")
	}
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 256 || strings.ContainsAny(id, "\r\n\x00") {
		return errors.New("ddout: run id is invalid")
	}
	runID, sequence, findingCount, runWriteErr = id, 0, 0, nil
	runStarted, runEnded = true, false
	return nil
}

// EndRun emits exactly one terminal run_summary for a started JSON run.
func EndRun(summary RunSummary) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	if !runStarted {
		return errors.New("ddout: no run started")
	}
	if runEnded {
		return errors.New("ddout: run already ended")
	}
	if err := summary.validate(); err != nil {
		return err
	}
	runEnded = true
	if OutputType != "json" {
		return nil
	}
	summary.Counts.Findings = findingCount
	sequence++
	record := JSONRecord{
		SchemaVersion: JSONSchemaVersion,
		RecordType:    "run_summary",
		Sequence:      sequence,
		RunID:         runID,
		Summary:       &summary,
	}
	err := writeTerminalJSONRecordLocked(&record)
	recordWriteErrorLocked(err)
	return err
}

func (summary RunSummary) validate() error {
	wantCode := map[string]int{"completed": 0, "failed": 1, "canceled": 130}
	code, ok := wantCode[summary.Status]
	if !ok || summary.ExitCode != code {
		return fmt.Errorf("ddout: invalid terminal status/exit code %q/%d", summary.Status, summary.ExitCode)
	}
	counts := []int64{
		summary.Counts.Targets, summary.Counts.Findings, summary.Counts.Coverage,
		summary.Counts.AssetsNew, summary.Counts.ServicesChanged, summary.Counts.AssetsDisappeared,
		summary.Counts.AssetsNotAssessed, summary.Counts.StagesExecuted, summary.Counts.StagesReused,
		summary.Counts.TargetsFull, summary.Counts.TargetsIncremental,
	}
	for _, count := range counts {
		if count < 0 {
			return errors.New("ddout: summary count is negative")
		}
	}
	return nil
}

// FormatOutput writes one finding. Output failures are reported to stderr so
// legacy void call sites cannot silently lose a record.
func FormatOutput(msg OutputMessage) {
	if err := FormatOutputE(msg); err != nil {
		gologger.Error().Msgf("write scan output: %s", err)
	}
}

// FormatOutputE is the error-returning form for callers that need to fail a
// run when a result cannot be serialized or written.
func FormatOutputE(msg OutputMessage) error {
	sinkMu.Lock()
	sink := outputSink
	sinkMu.Unlock()
	if sink != nil {
		sink(msg)
		return nil
	}

	writeMu.Lock()
	defer writeMu.Unlock()
	if OutputType == "json" {
		if !runStarted {
			return errors.New("ddout: JSON output requires BeginRun")
		}
		if runEnded {
			return errors.New("ddout: cannot write finding after EndRun")
		}
		sequence++
		if err := writeJSONRecordLocked(JSONRecord{
			SchemaVersion: JSONSchemaVersion,
			RecordType:    "finding",
			Sequence:      sequence,
			RunID:         runID,
			Finding:       jsonFinding(msg),
		}); err != nil {
			recordWriteErrorLocked(err)
			return err
		}
		findingCount++
		return nil
	}

	line := formatTextLine(msg)
	if line == "" {
		return nil
	}
	err := writeLineLocked(line)
	recordWriteErrorLocked(err)
	return err
}

func jsonFinding(msg OutputMessage) *JSONFinding {
	finding := &JSONFinding{
		Type: msg.Type, IP: msg.IP, IPs: msg.IPs, Port: msg.Port, Protocol: msg.Protocol,
		Finger: msg.Finger, Domain: msg.Domain, URI: msg.URI, City: msg.City,
		AdditionalMsg: msg.AdditionalMsg, Nuclei: msg.Nuclei,
	}
	if msg.Web.Status != "" || msg.Web.Title != "" {
		finding.Web = &JSONWeb{Status: msg.Web.Status, Title: msg.Web.Title}
	}
	if msg.GoPoc.PocName != "" || msg.GoPoc.Security != "" || msg.GoPoc.Description != "" || msg.GoPoc.Target != "" || msg.GoPoc.InfoLeft != "" || msg.GoPoc.InfoRight != "" || msg.GoPoc.ShowMsg != "" {
		finding.GoPoc = &JSONGoPoc{
			PocName: msg.GoPoc.PocName, Security: msg.GoPoc.Security, Description: msg.GoPoc.Description,
			Target: msg.GoPoc.Target, InfoLeft: msg.GoPoc.InfoLeft, InfoRight: msg.GoPoc.InfoRight, ShowMsg: msg.GoPoc.ShowMsg,
		}
	}
	return finding
}

func (finding JSONFinding) outputMessage() OutputMessage {
	msg := OutputMessage{
		Type: finding.Type, IP: finding.IP, IPs: finding.IPs, Port: finding.Port, Protocol: finding.Protocol,
		Finger: finding.Finger, Domain: finding.Domain, URI: finding.URI, City: finding.City,
		AdditionalMsg: finding.AdditionalMsg, Nuclei: finding.Nuclei,
	}
	if finding.Web != nil {
		msg.Web = WebInfo{Status: finding.Web.Status, Title: finding.Web.Title}
	}
	if finding.GoPoc != nil {
		msg.GoPoc = GoPocsResultType{
			PocName: finding.GoPoc.PocName, Security: finding.GoPoc.Security, Description: finding.GoPoc.Description,
			Target: finding.GoPoc.Target, InfoLeft: finding.GoPoc.InfoLeft, InfoRight: finding.GoPoc.InfoRight, ShowMsg: finding.GoPoc.ShowMsg,
		}
	}
	return msg
}

// DecodeFindingLine accepts both the versioned CLI record and the legacy
// top-level finding JSON used by historical result files. Summary lines are
// valid but return ok=false.
func DecodeFindingLine(line string) (message OutputMessage, ok bool, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return OutputMessage{}, false, nil
	}
	var header struct {
		SchemaVersion string `json:"schema_version"`
		RecordType    string `json:"record_type"`
	}
	if err := json.Unmarshal([]byte(line), &header); err != nil {
		return OutputMessage{}, false, err
	}
	if header.SchemaVersion == "" {
		var legacy OutputMessage
		if err := json.Unmarshal([]byte(line), &legacy); err != nil {
			return OutputMessage{}, false, err
		}
		return legacy, legacy.Type != "", nil
	}
	if header.SchemaVersion != JSONSchemaVersion {
		return OutputMessage{}, false, fmt.Errorf("unsupported CLI output schema %q", header.SchemaVersion)
	}
	var record JSONRecord
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		return OutputMessage{}, false, err
	}
	if record.RecordType == "run_summary" {
		return OutputMessage{}, false, nil
	}
	if record.RecordType != "finding" || record.Finding == nil {
		return OutputMessage{}, false, fmt.Errorf("invalid CLI finding record")
	}
	return record.Finding.outputMessage(), true, nil
}

func writeJSONRecordLocked(record JSONRecord) error {
	b, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal JSON output record: %w", err)
	}
	return writeLineLocked(string(b))
}

func writeTerminalJSONRecordLocked(record *JSONRecord) error {
	b, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal JSON output record: %w", err)
	}
	if OutputFileName == "" {
		if _, err := fmt.Fprintln(stdout, string(b)); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		return nil
	}

	file, offset, fileErr := appendTerminalRecord(OutputFileName, b)
	if fileErr != nil {
		failed, marshalErr := failedTerminalRecord(record)
		if marshalErr != nil {
			return errors.Join(fileErr, marshalErr)
		}
		if _, stdoutErr := fmt.Fprintln(stdout, string(failed)); stdoutErr != nil {
			return errors.Join(fileErr, fmt.Errorf("write stdout: %w", stdoutErr))
		}
		return fileErr
	}

	if _, stdoutErr := fmt.Fprintln(stdout, string(b)); stdoutErr != nil {
		failed, marshalErr := failedTerminalRecord(record)
		repairErr := marshalErr
		if marshalErr == nil {
			repairErr = replaceTerminalRecord(file, offset, failed)
		}
		_ = file.Close()
		return errors.Join(fmt.Errorf("write stdout: %w", stdoutErr), repairErr)
	}
	// The file was synced before stdout was published, so an eventual Close
	// error cannot make the two durable records disagree.
	_ = file.Close()
	return nil
}

func failedTerminalRecord(record *JSONRecord) ([]byte, error) {
	record.Summary.Status, record.Summary.ExitCode = "failed", 1
	b, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal failed terminal record: %w", err)
	}
	return b, nil
}

func appendTerminalRecord(filename string, record []byte) (*os.File, int64, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0o666)
	if err != nil {
		return nil, 0, fmt.Errorf("open output file: %w", err)
	}
	offset, err := file.Seek(0, io.SeekEnd)
	if err == nil {
		_, err = fmt.Fprintln(file, string(record))
	}
	if err == nil {
		err = file.Sync()
	}
	if err != nil {
		_ = file.Truncate(offset)
		_ = file.Close()
		return nil, 0, fmt.Errorf("append terminal output record: %w", err)
	}
	return file, offset, nil
}

func replaceTerminalRecord(file *os.File, offset int64, record []byte) error {
	if err := file.Truncate(offset); err != nil {
		return fmt.Errorf("remove stale terminal output record: %w", err)
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek terminal output record: %w", err)
	}
	if _, err := fmt.Fprintln(file, string(record)); err != nil {
		_ = file.Truncate(offset)
		return fmt.Errorf("write failed terminal output record: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Truncate(offset)
		return fmt.Errorf("sync failed terminal output record: %w", err)
	}
	return nil
}

func writeLineLocked(line string) error {
	if OutputFileName != "" {
		if err := appendToFile(OutputFileName, line); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
}

func recordWriteErrorLocked(err error) {
	if err != nil {
		runWriteErr = errors.Join(runWriteErr, err)
	}
}

// RunError returns output failures observed since BeginRun.
func RunError() error {
	writeMu.Lock()
	defer writeMu.Unlock()
	return runWriteErr
}

// Render returns the legacy text-mode line without writing it.
func Render(msg OutputMessage) string { return formatTextLine(msg) }

func formatTextLine(msg OutputMessage) string {
	switch msg.Type {
	case "IPAlive":
		if msg.AdditionalMsg != "" {
			return fmt.Sprintf("[Alive] %s (%s)", msg.IP, msg.AdditionalMsg)
		}
		return fmt.Sprintf("[Alive] %s", msg.IP)
	case "PortScan":
		return fmt.Sprintf("[Port] %s:%s", msg.IP, msg.Port)
	case "Protocol":
		return fmt.Sprintf("[Protocol] %s:%s %s", msg.IP, msg.Port, msg.Protocol)
	case "Web":
		parts := []string{fmt.Sprintf("[Web] %s", msg.URI)}
		if msg.Web.Status != "" {
			parts = append(parts, msg.Web.Status)
		}
		if msg.Web.Title != "" {
			parts = append(parts, msg.Web.Title)
		}
		if len(msg.Finger) > 0 {
			parts = append(parts, "["+strings.Join(msg.Finger, ",")+"]")
		}
		return strings.Join(parts, " ")
	case "Finger":
		return fmt.Sprintf("[Finger] %s [%s]", msg.URI, strings.Join(msg.Finger, ","))
	case "Active-Finger":
		line := fmt.Sprintf("[Active-Finger] %s [%s]", msg.URI, strings.Join(msg.Finger, ","))
		if msg.AdditionalMsg != "" {
			line += " " + msg.AdditionalMsg
		}
		return line
	case "Domain-Bind":
		if msg.Web.Status != "" {
			return fmt.Sprintf("[Domain-Bind] [%s] %s", msg.Web.Status, msg.URI)
		}
		return fmt.Sprintf("[Domain-Bind] %s", msg.URI)
	case "Nuclei":
		if msg.Show != "" {
			return fmt.Sprintf("[Nuclei] %s", msg.Show)
		}
		return fmt.Sprintf("[Nuclei] %s", msg.Nuclei)
	case "GoPoc":
		detail := strings.TrimSpace(msg.GoPoc.ShowMsg)
		if detail == "" {
			detail = strings.TrimSpace(fmt.Sprintf("%s %s %s", msg.GoPoc.Target, msg.GoPoc.PocName, msg.GoPoc.Description))
		}
		if msg.GoPoc.Security != "" {
			return fmt.Sprintf("[%s] %s", msg.GoPoc.Security, detail)
		}
		return fmt.Sprintf("[GoPoc] %s", detail)
	case "Domain":
		return fmt.Sprintf("[Domain] %s -> %s", msg.Domain, strings.Join(msg.IPs, ","))
	default:
		return msg.Show
	}
}

func appendToFile(filename, line string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, line); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	return nil
}

// resetForTest isolates package-global output state. It is intentionally
// unexported so production callers cannot reset an active run.
func resetForTest() {
	sinkMu.Lock()
	outputSink = nil
	sinkMu.Unlock()
	writeMu.Lock()
	OutputType, OutputFileName, stdout = "text", "", os.Stdout
	runID, sequence, findingCount, runStarted, runEnded, runWriteErr = "", 0, 0, false, false, nil
	writeMu.Unlock()
}

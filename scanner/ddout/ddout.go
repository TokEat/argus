// Package ddout provides the scanner output boundary.
//
// CLI text output remains human readable. CLI JSON output is UTF-8 NDJSON:
// each line is an independently decodable, versioned record. Agent callers
// continue to use SetOutputSink and receive the original OutputMessage.
package ddout

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/structs"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
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
	TargetsPartial     int64 `json:"targets_partial"`
	TargetsSkipped     int64 `json:"targets_skipped"`
	AssetsPlanned      int64 `json:"assets_planned"`
	AssetsSkipped      int64 `json:"assets_history_skipped"`
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
	Product       string     `json:"product,omitempty"`
	Version       string     `json:"version,omitempty"`
	Transport     string     `json:"transport,omitempty"`
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
	Status   string `json:"status,omitempty"`
	Title    string `json:"title,omitempty"`
	Cert     string `json:"cert,omitempty"`
	Size     string `json:"size,omitempty"`
	Redirect string `json:"redirect,omitempty"`
}

type JSONGoPoc struct {
	PocName     string                  `json:"poc_name,omitempty"`
	Security    string                  `json:"security,omitempty"`
	Description string                  `json:"description,omitempty"`
	Target      string                  `json:"target,omitempty"`
	InfoLeft    string                  `json:"info_left,omitempty"`
	InfoRight   string                  `json:"info_right,omitempty"`
	ShowMsg     string                  `json:"show_msg,omitempty"`
	Exchanges   []structs.GoPocExchange `json:"exchanges,omitempty"`
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

	writeMu             sync.Mutex
	stdout              io.Writer = os.Stdout
	runID               string
	sequence            uint64
	findingCount        int64
	runStarted          bool
	runEnded            bool
	runWriteErr         error
	protectedOutputPath string
	webBlocks           map[string]*webBlock
	webBlockOrder       []string
)

type webBlock struct {
	URI        string // canonical origin, used as the grouping key
	RawURI     string // first non-empty raw probe URI, used for the output line
	Web        WebInfo
	Fingers    []string
	FingerNote string
}

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
	runID, sequence, findingCount, runWriteErr, protectedOutputPath = id, 0, 0, nil, ""
	runStarted, runEnded = true, false
	resetWEBBlocksLocked()
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
	if err := flushWEBBlocksLocked(); err != nil {
		runEnded = true
		recordWriteErrorLocked(err)
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
		summary.Counts.TargetsFull, summary.Counts.TargetsIncremental, summary.Counts.TargetsPartial,
		summary.Counts.TargetsSkipped, summary.Counts.AssetsPlanned, summary.Counts.AssetsSkipped,
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

	if shouldBufferWEB(msg) {
		noteWEBLocked(msg)
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

func shouldBufferWEB(msg OutputMessage) bool {
	switch msg.Type {
	case "Web":
		return isHTTPWEBURI(msg.URI)
	case "Finger", "Active-Finger":
		return isHTTPWEBURI(msg.URI)
	default:
		return false
	}
}

func isHTTPWEBURI(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

// MergeWEBFingers attaches fingerprint names to a buffered WEB block so the
// later flush can print them under the original [WEB] header.
func MergeWEBFingers(uri string, fingers []string) {
	writeMu.Lock()
	defer writeMu.Unlock()
	if OutputType == "json" {
		return
	}
	noteWEBLocked(OutputMessage{Type: "Finger", URI: uri, Finger: append([]string(nil), fingers...)})
}

// FlushWEBBlocks writes one grouped [WEB] block per HTTP origin after fingerprinting.
func FlushWEBBlocks() error {
	writeMu.Lock()
	defer writeMu.Unlock()
	return flushWEBBlocksLocked()
}

func flushWEBBlocksLocked() error {
	if OutputType == "json" || len(webBlockOrder) == 0 {
		resetWEBBlocksLocked()
		return nil
	}
	for _, key := range webBlockOrder {
		block := webBlocks[key]
		if block == nil {
			continue
		}
		line := formatWEBBlock(block.outputMessage())
		if line == "" {
			continue
		}
		if err := writeLineLocked(line); err != nil {
			recordWriteErrorLocked(err)
			return err
		}
	}
	resetWEBBlocksLocked()
	return nil
}

func resetWEBBlocksLocked() {
	webBlocks = map[string]*webBlock{}
	webBlockOrder = nil
}

func noteWEBLocked(msg OutputMessage) {
	key := canonicalWEBOrigin(msg.URI)
	if key == "" {
		return
	}
	if webBlocks == nil {
		webBlocks = map[string]*webBlock{}
	}
	block, ok := webBlocks[key]
	if !ok {
		block = &webBlock{URI: key}
		webBlocks[key] = block
		webBlockOrder = append(webBlockOrder, key)
	}
	if block.RawURI == "" {
		block.RawURI = strings.TrimSpace(msg.URI)
	}
	applyWEBFields(block, msg)
	for _, finger := range msg.Finger {
		finger = strings.TrimSpace(finger)
		if finger == "" {
			continue
		}
		exists := false
		for _, existing := range block.Fingers {
			if existing == finger {
				exists = true
				break
			}
		}
		if !exists {
			block.Fingers = append(block.Fingers, finger)
		}
	}
	if msg.Type == "Active-Finger" && msg.AdditionalMsg != "" {
		block.FingerNote = strings.TrimSpace(msg.AdditionalMsg)
	}
}

func (block webBlock) outputMessage() OutputMessage {
	uri := block.URI
	if block.RawURI != "" {
		uri = block.RawURI
	}
	return OutputMessage{
		Type:          "Web",
		URI:           uri,
		Web:           block.Web,
		Finger:        append([]string(nil), block.Fingers...),
		AdditionalMsg: block.FingerNote,
	}
}

func applyWEBFields(block *webBlock, msg OutputMessage) {
	if block == nil {
		return
	}
	incoming := msg.Web
	newRank := webStatusRank(incoming.Status)
	oldRank := webStatusRank(block.Web.Status)
	if incoming.Status != "" && (block.Web.Status == "" || newRank > oldRank) {
		block.Web.Status = incoming.Status
		if incoming.Size != "" {
			block.Web.Size = incoming.Size
		}
		if incoming.Title != "" {
			block.Web.Title = incoming.Title
		}
	} else {
		if block.Web.Size == "" && incoming.Size != "" {
			block.Web.Size = incoming.Size
		}
		if block.Web.Title == "" && incoming.Title != "" {
			block.Web.Title = incoming.Title
		}
	}
	if incoming.Cert != "" && (block.Web.Cert == "" || newRank >= oldRank) {
		block.Web.Cert = incoming.Cert
	}
	if incoming.Redirect != "" && block.Web.Redirect == "" {
		block.Web.Redirect = incoming.Redirect
	}
}

func webStatusRank(status string) int {
	code, err := strconv.Atoi(strings.TrimSpace(status))
	if err != nil {
		return 0
	}
	switch {
	case code >= 200 && code < 300:
		return 3
	case code >= 400:
		return 2
	case code >= 300 && code < 400:
		return 1
	default:
		return 0
	}
}

func canonicalWEBURI(raw string) string {
	return canonicalWEBOrigin(raw)
}

func canonicalWEBOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return raw
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https":
	default:
		return ""
	}
	host := parsed.Hostname()
	if host == "" {
		return ""
	}
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	} else {
		parsed.Host = host
	}
	parsed.Scheme = scheme
	parsed.User = nil
	parsed.Path = "/"
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func jsonFinding(msg OutputMessage) *JSONFinding {
	finding := &JSONFinding{
		Type: msg.Type, IP: msg.IP, IPs: msg.IPs, Port: msg.Port, Protocol: msg.Protocol,
		Product: msg.Product, Version: msg.Version, Transport: msg.Transport,
		Finger: msg.Finger, Domain: msg.Domain, URI: msg.URI, City: msg.City,
		AdditionalMsg: msg.AdditionalMsg, Nuclei: msg.Nuclei,
	}
	if msg.Web.Status != "" || msg.Web.Title != "" || msg.Web.Cert != "" || msg.Web.Size != "" || msg.Web.Redirect != "" {
		finding.Web = &JSONWeb{Status: msg.Web.Status, Title: msg.Web.Title, Cert: msg.Web.Cert, Size: msg.Web.Size, Redirect: msg.Web.Redirect}
	}
	if msg.GoPoc.PocName != "" || msg.GoPoc.Security != "" || msg.GoPoc.Description != "" || msg.GoPoc.Target != "" || msg.GoPoc.InfoLeft != "" || msg.GoPoc.InfoRight != "" || msg.GoPoc.ShowMsg != "" || len(msg.GoPoc.Exchanges) > 0 {
		finding.GoPoc = &JSONGoPoc{
			PocName: msg.GoPoc.PocName, Security: msg.GoPoc.Security, Description: msg.GoPoc.Description,
			Target: msg.GoPoc.Target, InfoLeft: msg.GoPoc.InfoLeft, InfoRight: msg.GoPoc.InfoRight, ShowMsg: msg.GoPoc.ShowMsg,
			Exchanges: append([]structs.GoPocExchange(nil), msg.GoPoc.Exchanges...),
		}
	}
	return finding
}

func (finding JSONFinding) outputMessage() OutputMessage {
	msg := OutputMessage{
		Type: finding.Type, IP: finding.IP, IPs: finding.IPs, Port: finding.Port, Protocol: finding.Protocol,
		Product: finding.Product, Version: finding.Version, Transport: finding.Transport,
		Finger: finding.Finger, Domain: finding.Domain, URI: finding.URI, City: finding.City,
		AdditionalMsg: finding.AdditionalMsg, Nuclei: finding.Nuclei,
	}
	if finding.Web != nil {
		msg.Web = WebInfo{Status: finding.Web.Status, Title: finding.Web.Title, Cert: finding.Web.Cert, Size: finding.Web.Size, Redirect: finding.Web.Redirect}
	}
	if finding.GoPoc != nil {
		msg.GoPoc = GoPocsResultType{
			PocName: finding.GoPoc.PocName, Security: finding.GoPoc.Security, Description: finding.GoPoc.Description,
			Target: finding.GoPoc.Target, InfoLeft: finding.GoPoc.InfoLeft, InfoRight: finding.GoPoc.InfoRight, ShowMsg: finding.GoPoc.ShowMsg,
			Exchanges: append([]structs.GoPocExchange(nil), finding.GoPoc.Exchanges...),
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
	file, err := openPrivateOutputFile(filename, os.O_CREATE|os.O_RDWR)
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
	if _, err := fmt.Fprintln(stdout, colorizeFindingLine(line)); err != nil {
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

func displayServiceName(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "tcp", "udp", "unknown", "unidentified", "portscan", "protocol":
		return ""
	default:
		return strings.TrimSpace(protocol)
	}
}

func formatIPPort(ip, port string) string {
	ip = strings.TrimSpace(ip)
	port = strings.TrimSuffix(strings.TrimSpace(port), "/udp")
	if ip == "" {
		return port
	}
	if port == "" {
		return ip
	}
	return ip + ":" + port
}

// TransportLabel maps a finding to the text identifier after [Port]:
// [web], [udp], [tcp], or [other]. HTTP/HTTPS stay TCP on the wire.
func TransportLabel(transport string) string {
	return ServiceTag(transport, "")
}

// ServiceTag prefers application class over raw L4 transport so HTTP
// ports render as [web] without changing later Web/fingerprint stages.
func ServiceTag(transport, protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "http", "https", "http2", "ssl/http", "http-proxy", "http-alt":
		return "web"
	}
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "udp":
		return "udp"
	case "web":
		return "web"
	case "tcp", "":
		return "tcp"
	default:
		return "other"
	}
}

// ParseServiceLineRest reads an optional [tcp]/[udp]/[other] prefix and the
// first host:port token. Legacy "53/udp" suffixes are still recognized.
func ParseServiceLineRest(rest string) (transport, endpoint string) {
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end > 1 {
			tag := strings.ToLower(rest[1:end])
			switch tag {
			case "tcp", "udp", "web", "other":
				transport = tag
				rest = strings.TrimSpace(rest[end+1:])
			}
		}
	}
	endpoint = rest
	if i := strings.IndexAny(endpoint, " \t"); i >= 0 {
		endpoint = endpoint[:i]
	}
	endpoint = strings.TrimSpace(endpoint)
	if strings.HasSuffix(endpoint, "/udp") {
		transport = "udp"
		endpoint = strings.TrimSuffix(endpoint, "/udp")
	}
	return transport, endpoint
}

func formatPOCLine(msg OutputMessage) string {
	switch msg.Type {
	case "Nuclei":
		detail := strings.TrimSpace(msg.Show)
		if detail == "" {
			detail = strings.TrimSpace(msg.Nuclei)
		}
		if detail == "" {
			return ""
		}
		return "[POC] " + detail
	default:
		detail := strings.TrimSpace(msg.GoPoc.ShowMsg)
		if detail == "" {
			detail = strings.TrimSpace(strings.Join(nonEmptyPOC(msg.GoPoc.Target, msg.GoPoc.PocName, msg.GoPoc.Description), " "))
		}
		if detail == "" {
			return ""
		}
		if msg.GoPoc.Security != "" {
			return fmt.Sprintf("[POC] [%s] %s", msg.GoPoc.Security, detail)
		}
		return "[POC] " + detail
	}
}

func nonEmptyPOC(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func formatServiceFingerLine(msg OutputMessage) string {
	uri := strings.TrimSpace(msg.URI)
	if uri == "" {
		uri = formatIPPort(msg.IP, msg.Port)
	}
	line := "[Finger] " + uri
	if names := formatWEBFinger(msg); names != "" {
		return line + " " + names
	}
	return line
}

func formatWEBBlock(msg OutputMessage) string {
	uri := strings.TrimSpace(msg.URI)
	if uri == "" {
		uri = formatIPPort(msg.IP, msg.Port)
	}
	fields := []struct {
		key, value string
	}{
		{"Finger", formatWEBFinger(msg)},
		{"Certificates", strings.TrimSpace(msg.Web.Cert)},
		{"Code", strings.TrimSpace(msg.Web.Status)},
		{"Size", strings.TrimSpace(msg.Web.Size)},
		{"Redirect", displayRedirect(uri, msg.Web.Redirect)},
		{"Title", strings.TrimSpace(msg.Web.Title)},
	}
	var b strings.Builder
	b.WriteString("[WEB] ")
	b.WriteString(uri)
	for _, field := range fields {
		if field.value == "" {
			continue
		}
		b.WriteString("\n     [")
		b.WriteString(field.key)
		b.WriteString("] ")
		b.WriteString(field.value)
	}
	return b.String()
}

func formatWEBFinger(msg OutputMessage) string {
	finger := strings.Join(msg.Finger, ",")
	if msg.AdditionalMsg != "" {
		return strings.TrimSpace(finger + " " + msg.AdditionalMsg)
	}
	return finger
}

func displayRedirect(origin, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	base, err := url.Parse(origin)
	loc, locErr := url.Parse(value)
	if err == nil && locErr == nil && base.Host != "" && loc.Host != "" {
		if strings.EqualFold(base.Scheme, loc.Scheme) && strings.EqualFold(base.Hostname(), loc.Hostname()) && effectiveWEBPort(base) == effectiveWEBPort(loc) {
			path := loc.RequestURI()
			if path == "" || path == origin {
				path = loc.Path
			}
			if path == "" {
				path = "/"
			}
			return compactRedirect(path)
		}
	}
	if err == nil && locErr == nil && !loc.IsAbs() {
		return compactRedirect(value)
	}
	return compactRedirect(value)
}

func effectiveWEBPort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func compactRedirect(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 180 {
		return value[:180]
	}
	return value
}

func formatTextLine(msg OutputMessage) string {
	switch msg.Type {
	case "IPAlive":
		if msg.AdditionalMsg != "" {
			return fmt.Sprintf("[Alive] %s (%s)", msg.IP, msg.AdditionalMsg)
		}
		return fmt.Sprintf("[Alive] %s", msg.IP)
	case "Path":
		path := strings.Join(msg.IPs, " -> ")
		if msg.AdditionalMsg != "" && path != "" {
			return fmt.Sprintf("[Path] %s %s %s", msg.IP, msg.AdditionalMsg, path)
		}
		if msg.AdditionalMsg != "" {
			return fmt.Sprintf("[Path] %s %s", msg.IP, msg.AdditionalMsg)
		}
		if path != "" {
			return fmt.Sprintf("[Path] %s %s", msg.IP, path)
		}
		return fmt.Sprintf("[Path] %s", msg.IP)
	case "Topo":
		if msg.AdditionalMsg != "" {
			return "[Topo] " + msg.AdditionalMsg
		}
		return "[Topo] " + strings.Join(msg.IPs, " -> ")
	case "PortScan", "Protocol", "Nmap":
		line := fmt.Sprintf("[Port] [%s] %s", ServiceTag(msg.Transport, msg.Protocol), formatIPPort(msg.IP, msg.Port))
		if proto := displayServiceName(msg.Protocol); proto != "" {
			line += " " + proto
		}
		if msg.AdditionalMsg != "" {
			return line + " " + msg.AdditionalMsg
		}
		if extra := strings.TrimSpace(msg.Product + " " + msg.Version); extra != "" {
			return line + " " + extra
		}
		return line
	case "Web", "Finger", "Active-Finger":
		if msg.Type != "Web" && !isHTTPWEBURI(msg.URI) {
			return formatServiceFingerLine(msg)
		}
		return formatWEBBlock(msg)
	case "Domain-Bind":
		if msg.Web.Status != "" {
			return fmt.Sprintf("[Domain-Bind] [%s] %s", msg.Web.Status, msg.URI)
		}
		return fmt.Sprintf("[Domain-Bind] %s", msg.URI)
	case "Nuclei", "GoPoc":
		return formatPOCLine(msg)
	case "Domain":
		return fmt.Sprintf("[Domain] %s -> %s", msg.Domain, strings.Join(msg.IPs, ","))
	default:
		return msg.Show
	}
}

func appendToFile(filename, line string) error {
	f, err := openPrivateOutputFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, line); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	return nil
}

func openPrivateOutputFile(filename string, flags int) (*os.File, error) {
	file, err := os.OpenFile(filename, flags, 0o600)
	if err != nil {
		return nil, err
	}
	if protectedOutputPath != filename {
		if err := protectOutputFile(filename); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("protect output file: %w", err)
		}
		protectedOutputPath = filename
	}
	return file, nil
}

// resetForTest isolates package-global output state. It is intentionally
// unexported so production callers cannot reset an active run.
func resetForTest() {
	sinkMu.Lock()
	outputSink = nil
	sinkMu.Unlock()
	writeMu.Lock()
	OutputType, OutputFileName, stdout = "text", "", os.Stdout
	runID, sequence, findingCount, runStarted, runEnded, runWriteErr, protectedOutputPath = "", 0, 0, false, false, nil, ""
	resetWEBBlocksLocked()
	writeMu.Unlock()
}

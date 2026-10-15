// Package report renders the standalone CLI's authoritative, offline HTML
// report from the same structured findings that are written to result.txt.
package report

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

const SchemaVersion = "argus.cli-report/v1"

const (
	categoryAssets          = "assets"
	categoryServices        = "services"
	categoryWeb             = "web"
	categoryFingerprints    = "fingerprints"
	categoryVulnerabilities = "vulnerabilities"
	categoryOther           = "other"
)

var categoryOrder = []string{
	categoryAssets,
	categoryServices,
	categoryWeb,
	categoryFingerprints,
	categoryVulnerabilities,
	categoryOther,
}

// Options identifies one CLI run and its two output artifacts. SourceFile is
// metadata only: the HTML renderer never parses or mutates result.txt.
type Options struct {
	Path       string
	RunID      string
	Targets    []string
	SourceFile string
	StartedAt  time.Time
}

// Summary records scan/report lifecycle state. The CLI's process-wide terminal
// status remains the exit code and machine run_summary because stdout or the
// result sink can still fail after this offline artifact is published.
type Summary struct {
	Status     string
	FinishedAt time.Time
	Plan       PlanSummary
}

type Counts struct {
	Records           int
	Assets            int
	Services          int
	Web               int
	Fingerprints      int
	FingerprintEvents int
	Vulnerabilities   int
	Other             int
	Critical          int
	High              int
	Medium            int
	Low               int
	Info              int
	Unknown           int
}

// Session is a run-scoped, concurrency-safe report collector. Findings are
// rendered into category-specific temporary spools so large runs do not retain
// complete request and response evidence in memory. Owner-only mode is applied
// where the host filesystem supports POSIX permissions.
type Session struct {
	mu sync.Mutex

	options      Options
	nonce        string
	spools       map[string]*os.File
	paths        map[string]string
	counts       Counts
	nextID       uint64
	fingerprints *fingerprintCollector

	firstErr error
	finished bool
	aborted  bool
}

type reportItem struct {
	ID            string
	Category      string
	Type          string
	TypeLabel     string
	Endpoint      string
	Link          string
	IP            string
	Port          string
	Transport     string
	Protocol      string
	Status        string
	Title         string
	Certificate   string
	Location      string
	Fingerprints  []string
	Details       string
	Fingerprint   *fingerprintView
	Vulnerability *vulnerabilityView
}

type vulnerabilityView struct {
	Engine        string
	Name          string
	TemplateID    string
	Severity      string
	SeverityClass string
	Target        string
	Link          string
	Description   string
	Impact        string
	Remediation   string
	Authors       string
	Tags          string
	Matcher       string
	Additional    string
	Extracted     []string
	References    []linkView
	Metadata      string
	Exchanges     []exchangeView
}

type exchangeView struct {
	Label    string
	Request  string
	Response string
}

type linkView struct {
	Label string
	URL   string
}

// NewSession creates per-run temporary spools next to the final report. The
// final HTML is written atomically by Finish.
func NewSession(options Options) (*Session, error) {
	options.Path = strings.TrimSpace(options.Path)
	options.RunID = strings.TrimSpace(options.RunID)
	options.SourceFile = strings.TrimSpace(options.SourceFile)
	if options.Path == "" {
		return nil, errors.New("report path is required")
	}
	extension := strings.ToLower(filepath.Ext(options.Path))
	if extension != ".html" && extension != ".htm" {
		return nil, errors.New("report path must use the .html or .htm extension")
	}
	if options.RunID == "" || len(options.RunID) > 256 || strings.ContainsAny(options.RunID, "\r\n\x00") {
		return nil, errors.New("report run id is invalid")
	}
	if pathsEqual(options.Path, options.SourceFile) {
		return nil, errors.New("report path must differ from the result file")
	}
	if options.StartedAt.IsZero() {
		options.StartedAt = time.Now()
	}
	options.StartedAt = options.StartedAt.UTC()
	options.Targets = cleanValues(options.Targets)

	directory := filepath.Dir(options.Path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, fmt.Errorf("create report directory: %w", err)
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, fmt.Errorf("create report CSP nonce: %w", err)
	}
	session := &Session{
		options:      options,
		nonce:        nonce,
		spools:       make(map[string]*os.File, len(categoryOrder)),
		paths:        make(map[string]string, len(categoryOrder)),
		fingerprints: newFingerprintCollector(),
	}
	for _, category := range categoryOrder {
		file, createErr := os.CreateTemp(directory, ".argus-report-"+category+"-*.part")
		if createErr != nil {
			_ = session.cleanupLocked()
			return nil, fmt.Errorf("create report %s spool: %w", category, createErr)
		}
		if chmodErr := protectReportFile(file.Name()); chmodErr != nil {
			_ = file.Close()
			_ = os.Remove(file.Name())
			_ = session.cleanupLocked()
			return nil, fmt.Errorf("protect report %s spool: %w", category, chmodErr)
		}
		session.spools[category] = file
		session.paths[category] = file.Name()
	}
	return session, nil
}

// Observe records one scanner finding. I/O errors are retained and surfaced by
// Finish so legacy output call sites do not need to change their signatures.
func (s *Session) Observe(message structs.OutputMessage) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || s.aborted || s.firstErr != nil {
		return
	}
	if message.Type == "Finger" || message.Type == "Active-Finger" {
		if observations := s.fingerprints.Add(message); observations > 0 {
			s.counts.FingerprintEvents += observations
			return
		}
	}
	item := normalizeMessage(message)
	file := s.spools[item.Category]
	if file == nil {
		s.firstErr = fmt.Errorf("report category %q is unavailable", item.Category)
		return
	}
	s.nextID++
	item.ID = fmt.Sprintf("record-%d", s.nextID)
	if err := itemHTMLTemplate.Execute(file, item); err != nil {
		s.firstErr = fmt.Errorf("render report item: %w", err)
		return
	}
	s.counts.add(item)
}

// Finish closes the spools and atomically publishes one self-contained report.
func (s *Session) Finish(summary Summary) (result error) {
	if s == nil {
		return errors.New("report session is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return errors.New("report session already finished")
	}
	if s.aborted {
		return errors.New("report session was aborted")
	}
	s.finished = true

	if summary.Status != "completed" && summary.Status != "failed" && summary.Status != "canceled" {
		return s.preserveEvidenceLocked(fmt.Errorf("invalid report status %q", summary.Status))
	}
	if summary.FinishedAt.IsZero() {
		summary.FinishedAt = time.Now()
	}
	summary.FinishedAt = summary.FinishedAt.UTC()
	if summary.FinishedAt.Before(s.options.StartedAt) {
		return s.preserveEvidenceLocked(errors.New("report finish time precedes start time"))
	}
	if s.firstErr != nil {
		return s.preserveEvidenceLocked(s.firstErr)
	}
	if err := s.flushFingerprintsLocked(); err != nil {
		return s.preserveEvidenceLocked(err)
	}
	for _, category := range categoryOrder {
		file := s.spools[category]
		if err := file.Sync(); err != nil {
			return s.preserveEvidenceLocked(fmt.Errorf("sync report %s spool: %w", category, err))
		}
		if err := file.Close(); err != nil {
			return s.preserveEvidenceLocked(fmt.Errorf("close report %s spool: %w", category, err))
		}
		s.spools[category] = nil
	}
	if err := s.renderLocked(summary); err != nil {
		return s.preserveEvidenceLocked(err)
	}
	return s.cleanupLocked()
}

func (s *Session) flushFingerprintsLocked() error {
	file := s.spools[categoryFingerprints]
	if file == nil {
		return fmt.Errorf("report category %q is unavailable", categoryFingerprints)
	}
	for _, item := range s.fingerprints.Items() {
		s.nextID++
		item.ID = fmt.Sprintf("record-%d", s.nextID)
		if err := itemHTMLTemplate.Execute(file, item); err != nil {
			return fmt.Errorf("render fingerprint report item: %w", err)
		}
		s.counts.add(item)
	}
	return nil
}

// Abort discards temporary spools. It is safe to defer after NewSession.
func (s *Session) Abort() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || s.aborted {
		return nil
	}
	s.aborted = true
	return s.cleanupLocked()
}

func (s *Session) renderLocked(summary Summary) (result error) {
	directory := filepath.Dir(s.options.Path)
	temp, err := os.CreateTemp(directory, ".argus-report-final-*.html.part")
	if err != nil {
		return fmt.Errorf("create final report: %w", err)
	}
	tempPath := temp.Name()
	tempClosed := false
	defer func() {
		if !tempClosed {
			result = errors.Join(result, temp.Close())
		}
		if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove report staging file %s: %w", tempPath, err))
		}
	}()
	if err := protectReportFile(temp.Name()); err != nil {
		return fmt.Errorf("protect final report: %w", err)
	}
	view := pageView{
		SchemaVersion: SchemaVersion,
		RunID:         s.options.RunID,
		Targets:       append([]string(nil), s.options.Targets...),
		SourceFile:    s.options.SourceFile,
		StartedAt:     formatTime(s.options.StartedAt),
		FinishedAt:    formatTime(summary.FinishedAt),
		Duration:      summary.FinishedAt.Sub(s.options.StartedAt).Round(time.Millisecond).String(),
		Status:        summary.Status,
		StatusLabel:   statusLabel(summary.Status),
		Counts:        s.counts,
		Plan:          summary.Plan,
		Nonce:         s.nonce,
	}
	if err := pageHeaderTemplate.Execute(temp, view); err != nil {
		return fmt.Errorf("render report header: %w", err)
	}
	for _, category := range categoryOrder {
		section := sectionFor(category, s.counts)
		if err := sectionHeaderTemplate.Execute(temp, section); err != nil {
			return fmt.Errorf("render report %s section: %w", category, err)
		}
		if section.Count == 0 {
			if err := emptySectionTemplate.Execute(temp, section); err != nil {
				return fmt.Errorf("render empty report %s section: %w", category, err)
			}
		} else {
			spool, openErr := os.Open(s.paths[category])
			if openErr != nil {
				return fmt.Errorf("open report %s spool: %w", category, openErr)
			}
			_, copyErr := io.Copy(temp, spool)
			closeErr := spool.Close()
			if copyErr != nil {
				return fmt.Errorf("copy report %s spool: %w", category, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close report %s reader: %w", category, closeErr)
			}
		}
		if _, err := io.WriteString(temp, "</div></section>\n"); err != nil {
			return fmt.Errorf("finish report %s section: %w", category, err)
		}
	}
	if err := pageFooterTemplate.Execute(temp, view); err != nil {
		return fmt.Errorf("render report footer: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync final report: %w", err)
	}
	closeErr := temp.Close()
	tempClosed = true
	if closeErr != nil {
		return fmt.Errorf("close final report: %w", closeErr)
	}
	// A same-directory hard link is an atomic, no-overwrite publication. Unlike
	// Stat followed by Rename, two concurrent runs cannot replace each other's
	// authoritative report on Unix.
	if err := os.Link(tempPath, s.options.Path); err != nil {
		return fmt.Errorf("publish final report: %w", err)
	}
	return nil
}

func (s *Session) cleanupLocked() error {
	var result error
	for _, category := range categoryOrder {
		if file := s.spools[category]; file != nil {
			result = errors.Join(result, file.Close())
			s.spools[category] = nil
		}
		if path := s.paths[category]; path != "" {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
		}
	}
	return result
}

func (s *Session) preserveEvidenceLocked(cause error) error {
	var closeErr error
	paths := make([]string, 0, len(categoryOrder))
	for _, category := range categoryOrder {
		if file := s.spools[category]; file != nil {
			closeErr = errors.Join(closeErr, file.Sync(), file.Close())
			s.spools[category] = nil
		}
		path := s.paths[category]
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		} else if !errors.Is(err, os.ErrNotExist) {
			closeErr = errors.Join(closeErr, err)
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return errors.Join(cause, closeErr)
	}
	return errors.Join(
		cause,
		closeErr,
		fmt.Errorf("report evidence preserved for recovery: %s", strings.Join(paths, ", ")),
	)
}

func normalizeMessage(message structs.OutputMessage) reportItem {
	switch message.Type {
	case "IPAlive":
		return reportItem{Category: categoryAssets, Type: message.Type, TypeLabel: "存活主机", Endpoint: message.IP, IP: message.IP, Location: message.City, Details: message.AdditionalMsg}
	case "Path":
		return reportItem{Category: categoryOther, Type: message.Type, TypeLabel: "路径", Endpoint: message.IP, IP: message.IP, Details: joinDetails(message.AdditionalMsg, strings.Join(cleanValues(message.IPs), " -> "))}
	case "Topo":
		return reportItem{Category: categoryOther, Type: message.Type, TypeLabel: "拓扑", Endpoint: firstNonEmpty(message.AdditionalMsg, strings.Join(cleanValues(message.IPs), " -> ")), Details: message.AdditionalMsg}
	case "Domain", "DNS-SubFinder", "DNS-Brute", "CDN-Domain", "RealIP":
		return reportItem{Category: categoryAssets, Type: message.Type, TypeLabel: "域名", Endpoint: message.Domain, Location: message.City, Details: joinDetails(strings.Join(cleanValues(message.IPs), ", "), message.AdditionalMsg)}
	case "PortScan", "Protocol", "Nmap":
		port := servicePort(message)
		return reportItem{Category: categoryServices, Type: message.Type, TypeLabel: "开放端口", Endpoint: endpoint(message.IP, port), IP: message.IP, Port: port, Transport: ddout.ServiceTag(message.Transport, message.Protocol), Protocol: message.Protocol, Location: message.City, Details: message.AdditionalMsg}
	case "Web", "Domain-Bind":
		return reportItem{Category: categoryWeb, Type: message.Type, TypeLabel: typeLabel(message.Type), Endpoint: message.URI, Link: safeHTTPURL(message.URI), IP: message.IP, Port: message.Port, Status: message.Web.Status, Title: message.Web.Title, Certificate: strings.TrimSpace(message.Web.Cert), Location: message.City, Fingerprints: cleanValues(message.Finger), Details: message.AdditionalMsg}
	case "Finger", "Active-Finger":
		return reportItem{Category: categoryFingerprints, Type: message.Type, TypeLabel: typeLabel(message.Type), Endpoint: message.URI, Link: safeHTTPURL(message.URI), IP: message.IP, Port: message.Port, Status: message.Web.Status, Title: message.Web.Title, Location: message.City, Fingerprints: cleanValues(message.Finger), Details: message.AdditionalMsg}
	case "Nuclei":
		return normalizeNuclei(message)
	case "GoPoc":
		return normalizeGoPoc(message.GoPoc)
	default:
		return reportItem{Category: categoryOther, Type: message.Type, TypeLabel: typeLabel(message.Type), Endpoint: firstNonEmpty(message.URI, endpoint(message.IP, message.Port), message.Domain), Link: safeHTTPURL(message.URI), IP: message.IP, Port: message.Port, Protocol: message.Protocol, Status: message.Web.Status, Title: message.Web.Title, Location: message.City, Fingerprints: cleanValues(message.Finger), Details: joinDetails(strings.Join(cleanValues(message.IPs), ", "), message.AdditionalMsg, message.Show)}
	}
}

func normalizeNuclei(message structs.OutputMessage) reportItem {
	var event nucleiOutput.ResultEvent
	if err := json.Unmarshal([]byte(message.Nuclei), &event); err != nil {
		name, severity := nucleiFallback(message)
		view := &vulnerabilityView{
			Engine: "Nuclei", Name: name, TemplateID: name,
			Severity: severity, SeverityClass: severityClass(severity),
			Target: firstNonEmpty(message.URI, message.Show), Link: safeHTTPURL(message.URI),
			Description: "结构化 Nuclei 证据无法解析，以下为原始输出。",
			Metadata:    message.Nuclei,
		}
		return reportItem{Category: categoryVulnerabilities, Type: "Nuclei", TypeLabel: "Nuclei", Endpoint: view.Target, Link: view.Link, Vulnerability: view}
	}
	severity := strings.ToUpper(strings.TrimSpace(event.Info.SeverityHolder.Severity.String()))
	if severity == "" || severity == "UNKNOWN" {
		_, severity = nucleiFallback(message)
	}
	target := firstNonEmpty(event.Matched, event.URL, event.Host, message.URI)
	view := &vulnerabilityView{
		Engine: "Nuclei", Name: firstNonEmpty(event.Info.Name, event.TemplateID, "Nuclei finding"),
		TemplateID: event.TemplateID, Severity: severity, SeverityClass: severityClass(severity),
		Target: target, Link: safeHTTPURL(target), Description: event.Info.Description,
		Impact: event.Info.Impact, Remediation: event.Info.Remediation,
		Authors: event.Info.Authors.String(), Tags: event.Info.Tags.String(),
		Matcher: firstNonEmpty(event.MatcherName, event.ExtractorName), Additional: event.Error,
		Extracted: cleanValues(event.ExtractedResults),
	}
	if event.Info.Reference != nil {
		for _, reference := range event.Info.Reference.ToSlice() {
			if reference = strings.TrimSpace(reference); reference != "" {
				view.References = append(view.References, linkView{Label: reference, URL: safeHTTPURL(reference)})
			}
		}
	}
	metadata := make(map[string]any, 3)
	if len(event.Info.Metadata) > 0 {
		metadata["template"] = event.Info.Metadata
	}
	if len(event.Metadata) > 0 {
		metadata["result"] = event.Metadata
	}
	if event.Info.Classification != nil {
		metadata["classification"] = event.Info.Classification
	}
	if interaction := event.Interaction; interaction != nil {
		interactionMetadata := map[string]any{
			"protocol":       interaction.Protocol,
			"unique-id":      interaction.UniqueID,
			"full-id":        interaction.FullId,
			"q-type":         interaction.QType,
			"smtp-from":      interaction.SMTPFrom,
			"remote-address": interaction.RemoteAddress,
			"timestamp":      interaction.Timestamp.UTC().Format(time.RFC3339Nano),
		}
		if len(interaction.AsnInfo) > 0 {
			interactionMetadata["asn-info"] = interaction.AsnInfo
		}
		metadata["interaction"] = interactionMetadata
	}
	if len(metadata) > 0 {
		if encoded, err := marshalReadableJSON(metadata); err == nil {
			view.Metadata = encoded
		}
	}
	if len(event.Packet) > 0 {
		indexes := make([]int, 0, len(event.Packet))
		for index := range event.Packet {
			indexes = append(indexes, index)
		}
		sort.Ints(indexes)
		for sequence, index := range indexes {
			pair := event.Packet[index]
			view.Exchanges = append(view.Exchanges, exchangeView{Label: fmt.Sprintf("证据 %d", sequence+1), Request: pair.Request, Response: pair.Response})
		}
		if (event.Request != "" || event.Response != "") && !containsExchange(view.Exchanges, event.Request, event.Response) {
			view.Exchanges = append(view.Exchanges, exchangeView{Label: "主请求与响应", Request: event.Request, Response: event.Response})
		}
	} else if event.Request != "" || event.Response != "" {
		view.Exchanges = append(view.Exchanges, exchangeView{Label: "请求与响应", Request: event.Request, Response: event.Response})
	}
	if interaction := event.Interaction; interaction != nil && (interaction.RawRequest != "" || interaction.RawResponse != "") {
		if !containsExchange(view.Exchanges, interaction.RawRequest, interaction.RawResponse) {
			view.Exchanges = append(view.Exchanges, exchangeView{Label: "OAST interaction", Request: interaction.RawRequest, Response: interaction.RawResponse})
		}
	}
	if event.CURLCommand != "" {
		view.Exchanges = append(view.Exchanges, exchangeView{Label: "复现命令", Request: event.CURLCommand})
	}
	return reportItem{Category: categoryVulnerabilities, Type: "Nuclei", TypeLabel: "Nuclei", Endpoint: target, Link: view.Link, IP: event.IP, Port: event.Port, Protocol: event.Scheme, Vulnerability: view}
}

func marshalReadableJSON(value any) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buffer.String(), "\n"), nil
}

func containsExchange(exchanges []exchangeView, request, response string) bool {
	for _, exchange := range exchanges {
		if exchange.Request == request && exchange.Response == response {
			return true
		}
	}
	return false
}

func normalizeGoPoc(result structs.GoPocsResultType) reportItem {
	severity := strings.ToUpper(strings.TrimSpace(result.Security))
	if severity == "" {
		severity = "UNKNOWN"
	}
	view := &vulnerabilityView{
		Engine: "GoPoc", Name: firstNonEmpty(result.PocName, "GoPoc finding"),
		TemplateID: result.PocName, Severity: severity, SeverityClass: severityClass(severity),
		Target: result.Target, Link: safeHTTPURL(result.Target), Description: result.Description,
		Additional: result.ShowMsg,
	}
	for index, exchange := range result.Exchanges {
		if exchange.Request == "" && exchange.Response == "" {
			continue
		}
		label := strings.TrimSpace(exchange.Label)
		if label == "" {
			label = fmt.Sprintf("GoPoc exchange %d", index+1)
		}
		if encoding := strings.TrimSpace(exchange.Encoding); encoding != "" {
			label += " · " + encoding
		}
		if !containsExchange(view.Exchanges, exchange.Request, exchange.Response) {
			view.Exchanges = append(view.Exchanges, exchangeView{Label: label, Request: exchange.Request, Response: exchange.Response})
		}
	}
	if (result.InfoLeft != "" || result.InfoRight != "") && !containsExchange(view.Exchanges, result.InfoLeft, result.InfoRight) {
		view.Exchanges = append(view.Exchanges, exchangeView{Label: "验证证据", Request: result.InfoLeft, Response: result.InfoRight})
	}
	return reportItem{Category: categoryVulnerabilities, Type: "GoPoc", TypeLabel: "GoPoc", Endpoint: result.Target, Link: view.Link, Details: result.ShowMsg, Vulnerability: view}
}

func (counts *Counts) add(item reportItem) {
	counts.Records++
	switch item.Category {
	case categoryAssets:
		counts.Assets++
	case categoryServices:
		counts.Services++
	case categoryWeb:
		counts.Web++
	case categoryFingerprints:
		counts.Fingerprints++
	case categoryVulnerabilities:
		counts.Vulnerabilities++
		severity := "UNKNOWN"
		if item.Vulnerability != nil {
			severity = strings.ToUpper(item.Vulnerability.Severity)
		}
		switch severity {
		case "CRITICAL":
			counts.Critical++
		case "HIGH":
			counts.High++
		case "MEDIUM":
			counts.Medium++
		case "LOW":
			counts.Low++
		case "INFO":
			counts.Info++
		default:
			counts.Unknown++
		}
	default:
		counts.Other++
	}
}

func typeLabel(value string) string {
	switch value {
	case "Web":
		return "Web 服务"
	case "Domain-Bind":
		return "域名绑定"
	case "Finger":
		return "被动指纹"
	case "Active-Finger":
		return "主动指纹"
	case "":
		return "其他"
	default:
		return value
	}
}

func nucleiFallback(message structs.OutputMessage) (string, string) {
	name := "Nuclei finding"
	severity := "UNKNOWN"
	text := strings.TrimSpace(message.Show)
	if strings.HasPrefix(text, "[") {
		if end := strings.Index(text, "]"); end > 1 {
			name = text[1:end]
			text = strings.TrimSpace(text[end+1:])
		}
		if strings.HasPrefix(text, "[") {
			if end := strings.Index(text, "]"); end > 1 {
				severity = strings.ToUpper(strings.TrimSpace(text[1:end]))
			}
		}
	}
	var minimal struct {
		TemplateID string `json:"template-id"`
		Severity   string `json:"severity"`
	}
	if json.Unmarshal([]byte(message.Nuclei), &minimal) == nil {
		name = firstNonEmpty(minimal.TemplateID, name)
		severity = strings.ToUpper(firstNonEmpty(minimal.Severity, severity))
	}
	return name, severity
}

func severityClass(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return "severity-critical"
	case "HIGH":
		return "severity-high"
	case "MEDIUM":
		return "severity-medium"
	case "LOW":
		return "severity-low"
	case "INFO":
		return "severity-info"
	default:
		return "severity-unknown"
	}
}

func safeHTTPURL(value string) string {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ""
	}
	return value
}

func servicePort(message structs.OutputMessage) string {
	return strings.TrimSuffix(strings.TrimSpace(message.Port), "/udp")
}

func endpoint(host, port string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return port
	}
	if port == "" {
		return host
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return net.JoinHostPort(host, port)
}

func cleanValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func joinDetails(values ...string) string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return strings.Join(result, "\n")
}

func newNonce() (string, error) {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(value), nil
}

func formatTime(value time.Time) string {
	return value.Local().Format("2006-01-02 15:04:05 MST")
}

func statusLabel(value string) string {
	switch value {
	case "completed":
		return "扫描完成"
	case "canceled":
		return "扫描已取消"
	default:
		return "扫描失败"
	}
}

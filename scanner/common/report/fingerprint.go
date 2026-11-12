package report

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/TokEat/argus/scanner/structs"
)

const (
	fingerprintSourcePassive  = "passive"
	fingerprintSourceBehavior = "behavior"
	fingerprintSourceActive   = "active"
	fingerprintSourceFallback = "fallback"
)

type fingerprintCollector struct {
	facts map[string]*fingerprintFact
}

type fingerprintFact struct {
	Service  string
	Link     string
	Product  string
	Sources  map[string]fingerprintSourceView
	Evidence map[string]fingerprintEvidenceView
}

type fingerprintView struct {
	Service      string
	Link         string
	Product      string
	StateLabel   string
	StateClass   string
	Sources      []fingerprintSourceView
	Evidence     []fingerprintEvidenceView
	EvidenceText string
}

type fingerprintSourceView struct {
	Key   string
	Label string
	Class string
}

type fingerprintEvidenceView struct {
	SourceLabel string
	SourceClass string
	Endpoint    string
	Link        string
	Status      string
	Title       string
	Details     string
}

func newFingerprintCollector() *fingerprintCollector {
	return &fingerprintCollector{facts: make(map[string]*fingerprintFact)}
}

// Add records one raw fingerprint event and returns the number of product
// observations it contained. The raw result stream remains unchanged; this
// collector only creates a compact HTML projection.
func (c *fingerprintCollector) Add(message structs.OutputMessage) int {
	if c == nil {
		return 0
	}
	products := cleanValues(message.Finger)
	if len(products) == 0 {
		return 0
	}

	service := fingerprintService(message.URI, message.IP, message.Port)
	if service == "" {
		service = "未标识目标"
	}
	source := fingerprintSource(message)
	evidence := fingerprintEvidence(message, source, service)

	for _, product := range products {
		key := strings.ToLower(service) + "\x00" + strings.ToLower(product)
		fact := c.facts[key]
		if fact == nil {
			fact = &fingerprintFact{
				Service:  service,
				Link:     safeHTTPURL(service),
				Product:  product,
				Sources:  make(map[string]fingerprintSourceView),
				Evidence: make(map[string]fingerprintEvidenceView),
			}
			c.facts[key] = fact
		}
		fact.Sources[source.Key] = source
		evidenceKey := strings.Join([]string{
			source.Key,
			strings.ToLower(evidence.Endpoint),
			evidence.Status,
			evidence.Title,
			evidence.Details,
		}, "\x00")
		fact.Evidence[evidenceKey] = evidence
	}
	return len(products)
}

func (c *fingerprintCollector) Items() []reportItem {
	if c == nil || len(c.facts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(c.facts))
	for key := range c.facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	items := make([]reportItem, 0, len(keys))
	for _, key := range keys {
		fact := c.facts[key]
		view := &fingerprintView{
			Service: fact.Service,
			Link:    fact.Link,
			Product: fact.Product,
		}
		for _, sourceKey := range []string{fingerprintSourcePassive, fingerprintSourceBehavior, fingerprintSourceActive, fingerprintSourceFallback} {
			if source, ok := fact.Sources[sourceKey]; ok {
				view.Sources = append(view.Sources, source)
			}
		}
		view.StateLabel, view.StateClass = fingerprintState(fact.Sources)

		evidenceKeys := make([]string, 0, len(fact.Evidence))
		for evidenceKey := range fact.Evidence {
			evidenceKeys = append(evidenceKeys, evidenceKey)
		}
		sort.Slice(evidenceKeys, func(i, j int) bool {
			left := fact.Evidence[evidenceKeys[i]]
			right := fact.Evidence[evidenceKeys[j]]
			if fingerprintSourceRank(left.SourceClass) != fingerprintSourceRank(right.SourceClass) {
				return fingerprintSourceRank(left.SourceClass) < fingerprintSourceRank(right.SourceClass)
			}
			if left.Endpoint != right.Endpoint {
				return left.Endpoint < right.Endpoint
			}
			return evidenceKeys[i] < evidenceKeys[j]
		})
		for _, evidenceKey := range evidenceKeys {
			view.Evidence = append(view.Evidence, fact.Evidence[evidenceKey])
		}
		view.EvidenceText = fmt.Sprintf("%d 条来源证据", len(view.Evidence))

		items = append(items, reportItem{
			Category:     categoryFingerprints,
			Type:         "Fingerprint",
			TypeLabel:    "指纹",
			Endpoint:     fact.Service,
			Link:         fact.Link,
			Fingerprints: []string{fact.Product},
			Fingerprint:  view,
		})
	}
	return items
}

func fingerprintSource(message structs.OutputMessage) fingerprintSourceView {
	if message.Type == "Active-Finger" {
		note := strings.ToLower(message.AdditionalMsg)
		if strings.Contains(note, "[dir-fallback]") {
			return fingerprintSourceView{Key: fingerprintSourceFallback, Label: "路径推断", Class: "source-fallback"}
		}
		if strings.Contains(note, "[behavior-probe:") {
			return fingerprintSourceView{Key: fingerprintSourceBehavior, Label: "行为探针", Class: "source-behavior"}
		}
		return fingerprintSourceView{Key: fingerprintSourceActive, Label: "主动路径", Class: "source-active"}
	}
	return fingerprintSourceView{Key: fingerprintSourcePassive, Label: "被动命中", Class: "source-passive"}
}

func fingerprintEvidence(message structs.OutputMessage, source fingerprintSourceView, service string) fingerprintEvidenceView {
	endpointValue := strings.TrimSpace(message.URI)
	if endpointValue == "" {
		endpointValue = service
	}
	details := strings.TrimSpace(message.AdditionalMsg)
	if source.Key == fingerprintSourceFallback {
		details = strings.TrimSpace(strings.ReplaceAll(details, "[dir-fallback]", ""))
		details = joinDetails("产品专用路径返回 HTTP 200，未通过产品指纹规则复核，不作为已识别、不调度 POC。", details)
	}
	if source.Key == fingerprintSourceActive {
		details = strings.TrimSpace(strings.ReplaceAll(details, "[directory-probe]", ""))
	}
	return fingerprintEvidenceView{
		SourceLabel: source.Label,
		SourceClass: source.Class,
		Endpoint:    endpointValue,
		Link:        safeHTTPURL(endpointValue),
		Status:      strings.TrimSpace(message.Web.Status),
		Title:       strings.TrimSpace(message.Web.Title),
		Details:     details,
	}
}

func fingerprintState(sources map[string]fingerprintSourceView) (string, string) {
	_, passive := sources[fingerprintSourcePassive]
	_, behavior := sources[fingerprintSourceBehavior]
	_, active := sources[fingerprintSourceActive]
	if passive && (active || behavior) {
		return "双源确认", "fingerprint-confirmed"
	}
	if passive {
		return "已识别", "fingerprint-confirmed"
	}
	if behavior {
		return "行为确认", "fingerprint-confirmed"
	}
	if active {
		return "主动路径命中", "fingerprint-suspected"
	}
	return "疑似", "fingerprint-suspected"
}

func fingerprintSourceRank(class string) int {
	switch class {
	case "source-passive":
		return 0
	case "source-behavior":
		return 1
	case "source-active":
		return 2
	default:
		return 3
	}
}

func fingerprintService(rawURI, ip, port string) string {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI != "" {
		if parsed, err := url.Parse(rawURI); err == nil && parsed.Scheme != "" && parsed.Hostname() != "" {
			scheme := strings.ToLower(parsed.Scheme)
			host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
			servicePort := parsed.Port()
			if servicePort == "" {
				switch scheme {
				case "http":
					servicePort = "80"
				case "https":
					servicePort = "443"
				}
			}
			authority := host
			if servicePort != "" {
				authority = net.JoinHostPort(host, servicePort)
			}
			return scheme + "://" + authority
		}
	}
	if value := endpoint(ip, port); value != "" {
		return value
	}
	return rawURI
}

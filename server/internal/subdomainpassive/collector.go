// Package subdomainpassive implements Server-side passive subdomain
// enumeration for domain batches. Collection runs once per domain before
// dispatch, is cached across tasks, and its results are sealed into the
// attempt config so Agents no longer query public passive sources
// (deduplicating work across concurrently dispatched Agents).
package subdomainpassive

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultSourceTimeout bounds a single source HTTP request.
	DefaultSourceTimeout = 15 * time.Second
	// DefaultDomainBudget bounds collection (sources + DNS validation) per domain.
	DefaultDomainBudget = 90 * time.Second
	// DefaultMaxSubdomains caps stored subdomains per domain to keep sealed
	// task configs bounded.
	DefaultMaxSubdomains = 5000
	// wildcardChecks matches the Scanner-side subfinder baseline (2 probes).
	wildcardChecks = 2
)

// SourceClient fetches raw hostname candidates for a domain from one public
// keyless source. Fetch is a field so tests can stub transport-level behavior.
type SourceClient struct {
	Name  string
	Fetch func(ctx context.Context, client *http.Client, domain string) ([]string, error)
}

// DefaultSources lists the keyless public sources in preference order.
// crt.sh is kept although it has frequent outages; failures are isolated.
func DefaultSources() []SourceClient {
	return []SourceClient{
		{Name: "crt.name", Fetch: fetchCRTName},
		{Name: "crtsh", Fetch: fetchCrtsh},
		{Name: "certspotter", Fetch: fetchCertspotter},
	}
}

func fetchCRTName(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://crt.name/v1/search?apex="+domain, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.name returned %s", resp.Status)
	}
	var hosts []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			hosts = append(hosts, line)
		}
	}
	return hosts, scanner.Err()
}

func fetchCrtsh(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned %s", resp.Status)
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decode crt.sh response: %w", err)
	}
	var hosts []string
	for _, row := range rows {
		hosts = append(hosts, strings.Split(row.NameValue, "\n")...)
	}
	return hosts, nil
}

func fetchCertspotter(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certspotter returned %s", resp.Status)
	}
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decode certspotter response: %w", err)
	}
	var hosts []string
	for _, row := range rows {
		hosts = append(hosts, row.DNSNames...)
	}
	return hosts, nil
}

// Collector enumerates one domain across sources and validates candidates
// with DNS resolution plus a wildcard baseline, mirroring the semantics of
// the Scanner-embedded subfinder (suffix filter, wildcard removal).
type Collector struct {
	HTTP    *http.Client
	Sources []SourceClient
	// LookupIP resolves a hostname; overridable for tests.
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
	// RandomLabel returns a random DNS label for wildcard probing.
	RandomLabel func() string

	SourceTimeout time.Duration
	DomainBudget  time.Duration
	MaxSubdomains int
}

func NewCollector() *Collector {
	return &Collector{
		HTTP:    &http.Client{Timeout: DefaultSourceTimeout},
		Sources: DefaultSources(),
		LookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		},
		RandomLabel:   func() string { return fmt.Sprintf("argus%d", rand.Int63()) },
		SourceTimeout: DefaultSourceTimeout,
		DomainBudget:  DefaultDomainBudget,
		MaxSubdomains: DefaultMaxSubdomains,
	}
}

// CollectResult carries the validated subdomain list and the sources that
// contributed at least one surviving candidate.
type CollectResult struct {
	Subdomains []string
	Sources    []string
}

// Collect runs all sources concurrently, normalizes and suffix-filters the
// union, then drops wildcard hits and unresolvable candidates. It fails only
// when no source returned usable data.
func (c *Collector) Collect(ctx context.Context, domain string) (CollectResult, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return CollectResult{}, fmt.Errorf("empty domain")
	}
	budget := c.DomainBudget
	if budget <= 0 {
		budget = DefaultDomainBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	rawBySource := c.fetchSources(ctx, domain)
	candidates := normalizeCandidates(rawBySource, domain)
	if len(candidates) == 0 {
		if len(rawBySource) == 0 {
			return CollectResult{}, fmt.Errorf("all passive sources failed for %s", domain)
		}
		// Sources answered but nothing matched the suffix: an empty but valid
		// result (e.g. a domain with no CT history).
		return CollectResult{Subdomains: []string{}}, nil
	}

	wildcardIPs, probeFailed := c.wildcardBaseline(ctx, domain)
	if probeFailed {
		// A resolver hiccup during the wildcard baseline cannot be
		// distinguished from "not wildcarded"; caching surviving candidates
		// could poison the domain for the whole TTL.
		return CollectResult{}, fmt.Errorf("wildcard baseline unavailable for %s", domain)
	}
	valid, infraErrors := c.validate(ctx, candidates, wildcardIPs)
	// A resolver outage must not poison the cache with an empty result.
	if infraErrors > 0 && len(valid) == 0 {
		return CollectResult{}, fmt.Errorf("dns validation unavailable for %s", domain)
	}
	sortStrings(valid)
	if c.MaxSubdomains > 0 && len(valid) > c.MaxSubdomains {
		valid = valid[:c.MaxSubdomains]
	}
	sources := survivingSources(rawBySource, valid)
	return CollectResult{Subdomains: valid, Sources: sources}, nil
}

// fetchSources queries every source in parallel and keeps per-source raw
// hostnames on success.
func (c *Collector) fetchSources(ctx context.Context, domain string) map[string][]string {
	type outcome struct {
		name  string
		hosts []string
	}
	timeout := c.SourceTimeout
	if timeout <= 0 {
		timeout = DefaultSourceTimeout
	}
	results := make(chan outcome, len(c.Sources))
	var wg sync.WaitGroup
	for _, source := range c.Sources {
		wg.Add(1)
		go func(source SourceClient) {
			defer wg.Done()
			srcCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			hosts, err := source.Fetch(srcCtx, c.HTTP, domain)
			if err != nil {
				return
			}
			select {
			case results <- outcome{name: source.Name, hosts: hosts}:
			case <-ctx.Done():
			}
		}(source)
	}
	wg.Wait()
	close(results)
	raw := make(map[string][]string, len(c.Sources))
	for item := range results {
		raw[item.name] = item.hosts
	}
	return raw
}

// normalizeCandidates lowercases, strips wildcard markers, enforces the
// "<something>.<domain>" suffix, and dedups.
func normalizeCandidates(rawBySource map[string][]string, domain string) []string {
	suffix := "." + domain
	seen := make(map[string]struct{})
	for _, hosts := range rawBySource {
		for _, raw := range hosts {
			value := strings.ToLower(strings.TrimSpace(raw))
			value = strings.TrimPrefix(value, "*.")
			value = strings.Trim(value, ".")
			if value == "" || !strings.HasSuffix(value, suffix) {
				continue
			}
			seen[value] = struct{}{}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sortStrings(values)
	return values
}

// wildcardBaseline resolves random non-existent labels; any answer marks the
// domain as wildcarded and collects the wildcard IPs to filter against. It
// reports whether any probe failed with an infrastructure error, which the
// caller must treat as "baseline unknown" rather than "not wildcarded".
func (c *Collector) wildcardBaseline(ctx context.Context, domain string) (map[string]struct{}, bool) {
	wildcardIPs := make(map[string]struct{})
	if c.RandomLabel == nil {
		return nil, true
	}
	for i := 0; i < wildcardChecks; i++ {
		ips, err := c.LookupIP(ctx, c.RandomLabel()+domain)
		if err != nil {
			if !isNotFoundError(err) {
				return nil, true
			}
			continue
		}
		for _, ip := range ips {
			wildcardIPs[ip.String()] = struct{}{}
		}
	}
	return wildcardIPs, false
}

// validate resolves candidates concurrently and keeps those that resolve to
// at least one IP outside the wildcard baseline. It reports infrastructure
// lookup errors separately from NXDOMAIN-style misses.
func (c *Collector) validate(ctx context.Context, candidates []string, wildcardIPs map[string]struct{}) ([]string, int) {
	var mu sync.Mutex
	var infraErrors int
	valid := make([]string, 0, len(candidates))
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, candidate := range candidates {
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			continue
		}
		go func(candidate string) {
			defer wg.Done()
			defer func() { <-sem }()
			ips, err := c.LookupIP(ctx, candidate)
			if err != nil {
				if !isNotFoundError(err) {
					mu.Lock()
					infraErrors++
					mu.Unlock()
				}
				return
			}
			for _, ip := range ips {
				if _, wildcard := wildcardIPs[ip.String()]; wildcard {
					return
				}
			}
			if len(ips) == 0 {
				return
			}
			mu.Lock()
			valid = append(valid, candidate)
			mu.Unlock()
		}(candidate)
	}
	wg.Wait()
	return valid, infraErrors
}

func isNotFoundError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

func survivingSources(rawBySource map[string][]string, valid []string) []string {
	present := make(map[string]struct{}, len(valid))
	for _, host := range valid {
		present[host] = struct{}{}
	}
	sources := make([]string, 0, len(rawBySource))
	for name := range rawBySource {
		for _, host := range rawBySource[name] {
			normalized := strings.ToLower(strings.TrimSpace(host))
			normalized = strings.TrimPrefix(normalized, "*.")
			normalized = strings.Trim(normalized, ".")
			if _, ok := present[normalized]; ok {
				sources = append(sources, name)
				break
			}
		}
	}
	sortStrings(sources)
	return sources
}

func sortStrings(values []string) {
	sort.Strings(values)
}

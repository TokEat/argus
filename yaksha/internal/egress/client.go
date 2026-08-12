// Package egress implements Yaksha's exact-target outbound network policy and
// transport-independent raw TCP connectors.
package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const MaxHTTPBodyBytes = 1 << 20
const MaxConnectionsPerRun = 32

type HTTPResult struct {
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"`
}

// Client is the worker-facing, high-level Egress API. Its implementation uses
// a raw Connector so HTTP/TLS and redirect policy remain inside Yaksha.
type Client interface {
	HTTPGet(context.Context, string, []string) (HTTPResult, error)
	Dial(context.Context, string, []string) (string, error)
}

type NetworkClient struct{ Connector Connector }
type DisabledClient struct{}

func NewDirectClient(resolver *net.Resolver, allowSpecial bool) Client {
	return NetworkClient{Connector: DirectConnector{Resolver: resolver, AllowSpecial: allowSpecial}}
}

func NewSOCKS5Client(rawURL string) (Client, error) {
	connector, err := NewSOCKS5Connector(rawURL)
	if err != nil {
		return nil, err
	}
	return NetworkClient{Connector: connector}, nil
}

func NewRelayUnavailableClient() Client {
	return NetworkClient{Connector: RelayUnavailableConnector{}}
}

func WithConnectionBudget(client Client, limit int64) Client {
	network, ok := client.(NetworkClient)
	if !ok || network.Connector == nil {
		return client
	}
	network.Connector = &BudgetConnector{Connector: network.Connector, Limit: limit}
	return network
}

func (c NetworkClient) HTTPGet(ctx context.Context, rawURL string, allowed []string) (HTTPResult, error) {
	requestURL, err := url.Parse(rawURL)
	if err != nil || requestURL.User != nil || requestURL.Hostname() == "" {
		return HTTPResult{}, fmt.Errorf("invalid HTTP target")
	}
	policy, err := policyTargets(allowed)
	if err != nil {
		return HTTPResult{}, err
	}
	requested, err := httpTarget(requestURL)
	if err != nil || !policy[requested] {
		return HTTPResult{}, fmt.Errorf("network target is not authorized")
	}
	if c.Connector == nil {
		return HTTPResult{}, fmt.Errorf("Yaksha egress connector is unavailable")
	}
	var requestedMu sync.RWMutex
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			requestedMu.RLock()
			current := requested
			requestedMu.RUnlock()
			opened, openErr := c.Connector.Open(dialCtx, OpenRequest{
				Host: current.host, Port: current.port, Protocol: current.scheme, Deadline: deadlineFromContext(dialCtx),
			})
			if openErr != nil {
				return nil, openErr
			}
			return opened.Conn, nil
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			redirected, parseErr := httpTarget(req.URL)
			if parseErr != nil || !policy[redirected] {
				return fmt.Errorf("redirect target is not authorized")
			}
			requestedMu.Lock()
			requested = redirected
			requestedMu.Unlock()
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return HTTPResult{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return HTTPResult{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxHTTPBodyBytes+1))
	if err != nil {
		return HTTPResult{}, err
	}
	if len(body) > MaxHTTPBodyBytes {
		return HTTPResult{}, fmt.Errorf("HTTP response body exceeds %d bytes", MaxHTTPBodyBytes)
	}
	return HTTPResult{StatusCode: response.StatusCode, Body: string(body)}, nil
}

func (c NetworkClient) Dial(ctx context.Context, address string, allowed []string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid TCP target")
	}
	requested := target{scheme: "tcp", host: normalizeHost(host), port: port}
	policy, err := policyTargets(allowed)
	if err != nil {
		return "", err
	}
	if !policy[requested] {
		return "", fmt.Errorf("network target is not authorized")
	}
	if c.Connector == nil {
		return "", fmt.Errorf("Yaksha egress connector is unavailable")
	}
	opened, err := c.Connector.Open(ctx, OpenRequest{
		Host: requested.host, Port: requested.port, Protocol: requested.scheme, Deadline: deadlineFromContext(ctx),
	})
	if err != nil {
		return "", err
	}
	defer opened.Conn.Close()
	return opened.Metadata.RemoteAddress, nil
}

func (DisabledClient) HTTPGet(context.Context, string, []string) (HTTPResult, error) {
	return HTTPResult{}, fmt.Errorf("Yaksha egress is disabled")
}

func (DisabledClient) Dial(context.Context, string, []string) (string, error) {
	return "", fmt.Errorf("Yaksha egress is disabled")
}

func deadlineFromContext(ctx context.Context) time.Time {
	deadline, _ := ctx.Deadline()
	return deadline
}

type target struct {
	scheme string
	host   string
	port   string
}

func ValidateTargets(values []string) error {
	seen := map[target]bool{}
	for _, value := range values {
		parsed, err := parseTarget(value)
		if err != nil {
			return err
		}
		if seen[parsed] {
			return fmt.Errorf("network target is duplicated")
		}
		seen[parsed] = true
	}
	return nil
}

func policyTargets(values []string) (map[target]bool, error) {
	result := make(map[target]bool, len(values))
	for _, value := range values {
		parsed, err := parseTarget(value)
		if err != nil {
			return nil, err
		}
		result[parsed] = true
	}
	return result, nil
}

func parseTarget(value string) (target, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return target{}, fmt.Errorf("network target must be an exact scheme://host:port origin")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "tcp" {
		return target{}, fmt.Errorf("network target has unsupported scheme")
	}
	portNumber, err := strconv.Atoi(parsed.Port())
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return target{}, fmt.Errorf("network target has invalid port")
	}
	return target{scheme: scheme, host: normalizeHost(parsed.Hostname()), port: parsed.Port()}, nil
}

func httpTarget(parsed *url.URL) (target, error) {
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return target{}, fmt.Errorf("unsupported HTTP scheme")
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return target{scheme: scheme, host: normalizeHost(parsed.Hostname()), port: port}, nil
}

func normalizeHost(host string) string { return strings.ToLower(strings.TrimSuffix(host, ".")) }

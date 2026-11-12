// Package egress implements Yaksha's exact-target outbound network policy and
// transport-independent raw TCP connectors.
package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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
const MaxHTTPHeaderBytes = 64 << 10
const MaxConnectionsPerRun = 32
const MaxTCPWriteBytes = 256 << 10
const MaxTCPResponseBytes = 1 << 20
const MaxTCPSteps = 16

type HTTPRequest struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	BodyEncoding    string            `json:"body_encoding,omitempty"`
	FollowRedirects bool              `json:"follow_redirects,omitempty"`
}

type HTTPResult struct {
	StatusCode   int                 `json:"status_code"`
	FinalURL     string              `json:"final_url"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body"`
	BodyEncoding string              `json:"body_encoding"`
}

type TCPExchangeRequest struct {
	Address          string    `json:"address"`
	Steps            []TCPStep `json:"steps"`
	MaxResponseBytes int       `json:"max_response_bytes,omitempty"`
}

type TCPStep struct {
	Operation     string `json:"operation"`
	Data          string `json:"data,omitempty"`
	Encoding      string `json:"encoding,omitempty"`
	Until         string `json:"until,omitempty"`
	UntilEncoding string `json:"until_encoding,omitempty"`
	MaxBytes      int    `json:"max_bytes,omitempty"`
	IdleTimeoutMS int    `json:"idle_timeout_ms,omitempty"`
}

type TCPExchangeResult struct {
	RemoteAddress string   `json:"remote_address"`
	Responses     []string `json:"responses"`
	Encodings     []string `json:"encodings"`
}

// Client is the worker-facing, high-level Egress API. Its implementation uses
// a raw Connector so HTTP/TLS and redirect policy remain inside Yaksha.
type Client interface {
	HTTPGet(context.Context, string, []string) (HTTPResult, error)
	Dial(context.Context, string, []string) (string, error)
}

type ExtendedClient interface {
	Client
	HTTPRequest(context.Context, HTTPRequest, []string) (HTTPResult, error)
	TCPExchange(context.Context, TCPExchangeRequest, []string) (TCPExchangeResult, error)
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
	return c.HTTPRequest(ctx, HTTPRequest{Method: http.MethodGet, URL: rawURL, FollowRedirects: true}, allowed)
}

func (c NetworkClient) HTTPRequest(ctx context.Context, input HTTPRequest, allowed []string) (HTTPResult, error) {
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if !allowedMethod(method) {
		return HTTPResult{}, fmt.Errorf("unsupported HTTP method")
	}
	requestURL, err := url.Parse(input.URL)
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
		Proxy: nil, MaxResponseHeaderBytes: MaxHTTPHeaderBytes,
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
			if !input.FollowRedirects {
				return http.ErrUseLastResponse
			}
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
	body, err := decodePayload(input.Body, input.BodyEncoding)
	if err != nil || len(body) > MaxHTTPBodyBytes {
		return HTTPResult{}, fmt.Errorf("invalid HTTP request body")
	}
	request, err := http.NewRequestWithContext(ctx, method, input.URL, bytes.NewReader(body))
	if err != nil {
		return HTTPResult{}, err
	}
	headerBytes := 0
	for name, value := range input.Headers {
		if !safeHeader(name, value) {
			return HTTPResult{}, fmt.Errorf("unsafe HTTP header")
		}
		headerBytes += len(name) + len(value) + 4
		if headerBytes > MaxHTTPHeaderBytes {
			return HTTPResult{}, fmt.Errorf("HTTP request headers exceed %d bytes", MaxHTTPHeaderBytes)
		}
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return HTTPResult{}, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, MaxHTTPBodyBytes+1))
	if err != nil {
		return HTTPResult{}, err
	}
	if len(responseBody) > MaxHTTPBodyBytes {
		return HTTPResult{}, fmt.Errorf("HTTP response body exceeds %d bytes", MaxHTTPBodyBytes)
	}
	encoded, encoding := encodePayload(responseBody)
	return HTTPResult{StatusCode: response.StatusCode, FinalURL: response.Request.URL.String(), Headers: response.Header.Clone(), Body: encoded, BodyEncoding: encoding}, nil
}

func (c NetworkClient) Dial(ctx context.Context, address string, allowed []string) (string, error) {
	result, err := c.TCPExchange(ctx, TCPExchangeRequest{Address: address}, allowed)
	return result.RemoteAddress, err
}

func (c NetworkClient) TCPExchange(ctx context.Context, input TCPExchangeRequest, allowed []string) (TCPExchangeResult, error) {
	address := input.Address
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return TCPExchangeResult{}, fmt.Errorf("invalid TCP target")
	}
	requested := target{scheme: "tcp", host: normalizeHost(host), port: port}
	policy, err := policyTargets(allowed)
	if err != nil {
		return TCPExchangeResult{}, err
	}
	if !policy[requested] {
		return TCPExchangeResult{}, fmt.Errorf("network target is not authorized")
	}
	if c.Connector == nil {
		return TCPExchangeResult{}, fmt.Errorf("Yaksha egress connector is unavailable")
	}
	if len(input.Steps) > MaxTCPSteps {
		return TCPExchangeResult{}, fmt.Errorf("TCP exchange exceeds %d steps", MaxTCPSteps)
	}
	limit := input.MaxResponseBytes
	if limit == 0 {
		limit = MaxTCPResponseBytes
	}
	if limit < 1 || limit > MaxTCPResponseBytes {
		return TCPExchangeResult{}, fmt.Errorf("invalid max_response_bytes")
	}
	opened, err := c.Connector.Open(ctx, OpenRequest{
		Host: requested.host, Port: requested.port, Protocol: requested.scheme, Deadline: deadlineFromContext(ctx),
	})
	if err != nil {
		return TCPExchangeResult{}, err
	}
	defer opened.Conn.Close()
	result := TCPExchangeResult{RemoteAddress: opened.Metadata.RemoteAddress, Responses: []string{}, Encodings: []string{}}
	reader := bufio.NewReader(opened.Conn)
	written, read := 0, 0
	for _, step := range input.Steps {
		if step.IdleTimeoutMS < 0 || step.IdleTimeoutMS > 30_000 {
			return TCPExchangeResult{}, fmt.Errorf("invalid TCP idle timeout")
		}
		if step.IdleTimeoutMS > 0 {
			_ = opened.Conn.SetDeadline(time.Now().Add(time.Duration(step.IdleTimeoutMS) * time.Millisecond))
		} else {
			_ = opened.Conn.SetDeadline(deadlineFromContext(ctx))
		}
		switch step.Operation {
		case "write":
			data, decodeErr := decodePayload(step.Data, step.Encoding)
			if decodeErr != nil || written+len(data) > MaxTCPWriteBytes {
				return TCPExchangeResult{}, fmt.Errorf("invalid TCP write payload")
			}
			if _, err = opened.Conn.Write(data); err != nil {
				return TCPExchangeResult{}, err
			}
			written += len(data)
		case "read":
			stepLimit := step.MaxBytes
			if stepLimit == 0 {
				stepLimit = limit - read
			}
			if stepLimit < 1 || stepLimit > limit-read {
				return TCPExchangeResult{}, fmt.Errorf("invalid TCP read limit")
			}
			var data []byte
			if step.Until != "" {
				delim, decodeErr := decodePayload(step.Until, step.UntilEncoding)
				if decodeErr != nil || len(delim) == 0 {
					return TCPExchangeResult{}, fmt.Errorf("invalid TCP read delimiter")
				}
				data, err = readUntil(reader, delim, stepLimit)
			} else {
				buf := make([]byte, stepLimit)
				var n int
				n, err = reader.Read(buf)
				data = buf[:n]
			}
			if err != nil && err != io.EOF {
				return TCPExchangeResult{}, err
			}
			read += len(data)
			value, encoding := encodePayload(data)
			result.Responses = append(result.Responses, value)
			result.Encodings = append(result.Encodings, encoding)
		case "half_close":
			if closer, ok := opened.Conn.(interface{ CloseWrite() error }); ok {
				if err := closer.CloseWrite(); err != nil {
					return TCPExchangeResult{}, err
				}
			} else {
				return TCPExchangeResult{}, fmt.Errorf("TCP half-close is unavailable")
			}
		default:
			return TCPExchangeResult{}, fmt.Errorf("unsupported TCP step")
		}
	}
	return result, nil
}

func (DisabledClient) HTTPRequest(context.Context, HTTPRequest, []string) (HTTPResult, error) {
	return HTTPResult{}, fmt.Errorf("Yaksha egress is disabled")
}
func (DisabledClient) TCPExchange(context.Context, TCPExchangeRequest, []string) (TCPExchangeResult, error) {
	return TCPExchangeResult{}, fmt.Errorf("Yaksha egress is disabled")
}
func (DisabledClient) HTTPGet(context.Context, string, []string) (HTTPResult, error) {
	return HTTPResult{}, fmt.Errorf("Yaksha egress is disabled")
}

func allowedMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	}
	return false
}
func safeHeader(name, value string) bool {
	if strings.ContainsAny(name+value, "\r\n") {
		return false
	}
	if name == "" {
		return false
	}
	for _, char := range name {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", char)) {
			return false
		}
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "connection", "proxy-authorization", "proxy-authenticate", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host":
		return false
	}
	return true
}
func decodePayload(value, encoding string) ([]byte, error) {
	if encoding == "" || encoding == "utf8" {
		return []byte(value), nil
	}
	if encoding == "base64" {
		return base64.StdEncoding.DecodeString(value)
	}
	return nil, fmt.Errorf("unsupported encoding")
}
func encodePayload(value []byte) (string, string) {
	if strings.ToValidUTF8(string(value), "") == string(value) {
		return string(value), "utf8"
	}
	return base64.StdEncoding.EncodeToString(value), "base64"
}
func readUntil(reader *bufio.Reader, delimiter []byte, limit int) ([]byte, error) {
	var out []byte
	for len(out) < limit {
		b, err := reader.ReadByte()
		if err != nil {
			return out, err
		}
		out = append(out, b)
		if bytes.HasSuffix(out, delimiter) {
			return out, nil
		}
	}
	return nil, fmt.Errorf("TCP response delimiter not found within %d bytes", limit)
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

package egress

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// OpenRequest is the transport-independent input for one authorized raw TCP
// connection. Agent relay support will implement this same interface later.
type OpenRequest struct {
	Host     string
	Port     string
	Protocol string
	Deadline time.Time
}

type OpenMetadata struct {
	Mode          string
	ResolvedIP    string
	RemoteAddress string
}

type OpenResult struct {
	Conn     net.Conn
	Metadata OpenMetadata
}

type Connector interface {
	Open(context.Context, OpenRequest) (OpenResult, error)
}

type DirectConnector struct {
	Resolver     *net.Resolver
	AllowSpecial bool
	DialContext  func(context.Context, string) (net.Conn, error)
}

type SOCKS5Connector struct {
	resolver     *net.Resolver
	allowSpecial bool
	dialer       proxy.ContextDialer
}

type RelayUnavailableConnector struct{}

type BudgetConnector struct {
	Connector Connector
	Limit     int64
	used      atomic.Int64
}

func (c *BudgetConnector) Open(ctx context.Context, request OpenRequest) (OpenResult, error) {
	if c == nil || c.Connector == nil || c.Limit < 1 {
		return OpenResult{}, fmt.Errorf("Yaksha egress connector is unavailable")
	}
	if c.used.Add(1) > c.Limit {
		return OpenResult{}, fmt.Errorf("network connection budget exceeds %d", c.Limit)
	}
	return c.Connector.Open(ctx, request)
}

func (c DirectConnector) Open(ctx context.Context, request OpenRequest) (OpenResult, error) {
	return openResolved(ctx, request, c.Resolver, c.AllowSpecial, "direct", func(openCtx context.Context, address string) (net.Conn, error) {
		if c.DialContext != nil {
			return c.DialContext(openCtx, address)
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		return dialer.DialContext(openCtx, "tcp", address)
	})
}

func NewSOCKS5Connector(rawURL string) (Connector, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme != "socks5" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("SOCKS5 proxy must be socks5://[user:password@]host:port")
	}
	var auth *proxy.Auth
	if parsed.User != nil {
		password, _ := parsed.User.Password()
		auth = &proxy.Auth{User: parsed.User.Username(), Password: password}
	}
	dialer, err := proxy.SOCKS5("tcp", parsed.Host, auth, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("configure Yaksha SOCKS5 proxy")
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("configured SOCKS5 implementation does not support cancellation")
	}
	return SOCKS5Connector{dialer: contextDialer}, nil
}

func (c SOCKS5Connector) Open(ctx context.Context, request OpenRequest) (OpenResult, error) {
	return openResolved(ctx, request, c.resolver, c.allowSpecial, "socks5", func(openCtx context.Context, address string) (net.Conn, error) {
		return c.dialer.DialContext(openCtx, "tcp", address)
	})
}

func (RelayUnavailableConnector) Open(context.Context, OpenRequest) (OpenResult, error) {
	return OpenResult{}, fmt.Errorf("Agent Egress Unavailable: relay provider is not configured")
}

func openResolved(
	ctx context.Context,
	request OpenRequest,
	resolver *net.Resolver,
	allowSpecial bool,
	mode string,
	dial func(context.Context, string) (net.Conn, error),
) (OpenResult, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	openCtx := ctx
	cancel := func() {}
	if !request.Deadline.IsZero() {
		openCtx, cancel = context.WithDeadline(ctx, request.Deadline)
	}
	defer cancel()
	addresses, err := resolver.LookupIPAddr(openCtx, request.Host)
	if err != nil {
		return OpenResult{}, fmt.Errorf("resolve network target: %w", err)
	}
	var lastErr error
	allowedAddress := false
	for _, address := range addresses {
		if !allowSpecial && forbidden(address.IP) {
			continue
		}
		allowedAddress = true
		targetAddress := net.JoinHostPort(address.IP.String(), request.Port)
		connection, dialErr := dial(openCtx, targetAddress)
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		return OpenResult{
			Conn: connection,
			Metadata: OpenMetadata{
				Mode: mode, ResolvedIP: address.IP.String(), RemoteAddress: connection.RemoteAddr().String(),
			},
		}, nil
	}
	if !allowedAddress {
		return OpenResult{}, fmt.Errorf("network target resolves only to forbidden addresses")
	}
	if lastErr != nil {
		return OpenResult{}, lastErr
	}
	return OpenResult{}, fmt.Errorf("network target has no usable address")
}

func forbidden(ip net.IP) bool {
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, metadataIP := range []net.IP{
		net.ParseIP("169.254.169.254"),
		net.ParseIP("100.100.100.200"),
		net.ParseIP("192.0.0.192"),
		net.ParseIP("fd00:ec2::254"),
	} {
		if ip.Equal(metadataIP) {
			return true
		}
	}
	return false
}

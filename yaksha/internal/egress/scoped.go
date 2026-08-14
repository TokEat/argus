package egress

import (
	"context"
	"sync"
)

// ScopedClient selects one Egress client while a long-lived worker is checked
// out for exactly one top-level request.
type ScopedClient struct {
	mu      sync.RWMutex
	current Client
	ctx     context.Context
}

func (c *ScopedClient) Set(client Client) {
	c.SetContext(context.Background(), client)
}

func (c *ScopedClient) SetContext(ctx context.Context, client Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client == nil {
		client = DisabledClient{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.current = client
	c.ctx = ctx
}

func (c *ScopedClient) Clear() { c.Set(DisabledClient{}) }

func (c *ScopedClient) selected() (context.Context, Client) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.current == nil {
		return context.Background(), DisabledClient{}
	}
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx, c.current
}

func (c *ScopedClient) HTTPGet(_ context.Context, target string, allowed []string) (HTTPResult, error) {
	ctx, client := c.selected()
	return client.HTTPGet(ctx, target, allowed)
}

func (c *ScopedClient) Dial(_ context.Context, target string, allowed []string) (string, error) {
	ctx, client := c.selected()
	return client.Dial(ctx, target, allowed)
}

func (c *ScopedClient) HTTPRequest(_ context.Context, input HTTPRequest, allowed []string) (HTTPResult, error) {
	ctx, client := c.selected()
	extended, ok := client.(ExtendedClient)
	if !ok {
		return HTTPResult{}, context.Canceled
	}
	return extended.HTTPRequest(ctx, input, allowed)
}

func (c *ScopedClient) TCPExchange(_ context.Context, input TCPExchangeRequest, allowed []string) (TCPExchangeResult, error) {
	ctx, client := c.selected()
	extended, ok := client.(ExtendedClient)
	if !ok {
		return TCPExchangeResult{}, context.Canceled
	}
	return extended.TCPExchange(ctx, input, allowed)
}

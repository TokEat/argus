package egress

import (
	"context"
	"net"
	"testing"
)

type stubClient struct{}

func (stubClient) HTTPGet(context.Context, string, []string) (HTTPResult, error) {
	return HTTPResult{StatusCode: 201, Body: "ok"}, nil
}
func (stubClient) Dial(context.Context, string, []string) (string, error) {
	return "192.0.2.1:443", nil
}

func TestIPCRoundTrip(t *testing.T) {
	server, worker := net.Pipe()
	defer server.Close()
	defer worker.Close()
	go func() { _ = ServeIPC(server, stubClient{}) }()
	client := NewIPCClient(worker)
	httpResult, err := client.HTTPGet(context.Background(), "https://example.invalid", nil)
	if err != nil || httpResult.StatusCode != 201 || httpResult.Body != "ok" {
		t.Fatalf("result=%#v err=%v", httpResult, err)
	}
	dialResult, err := client.Dial(context.Background(), "example.invalid:443", nil)
	if err != nil || dialResult != "192.0.2.1:443" {
		t.Fatalf("result=%q err=%v", dialResult, err)
	}
}

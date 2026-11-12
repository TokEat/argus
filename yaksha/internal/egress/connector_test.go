package egress

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestDirectConnectorPinsResolvedPrivateIP(t *testing.T) {
	var connected string
	connector := DirectConnector{DialContext: func(_ context.Context, address string) (net.Conn, error) {
		connected = address
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		return client, nil
	}}
	opened, err := connector.Open(context.Background(), OpenRequest{Host: "10.0.0.8", Port: "443", Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Conn.Close()
	if connected != "10.0.0.8:443" || opened.Metadata.ResolvedIP != "10.0.0.8" || opened.Metadata.Mode != "direct" {
		t.Fatalf("address=%q metadata=%#v", connected, opened.Metadata)
	}
}

func TestConnectorRejectsSpecialAndMetadataAddresses(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "100.100.100.200", "192.0.0.192", "fd00:ec2::254", "224.0.0.1", "0.0.0.0"} {
		t.Run(host, func(t *testing.T) {
			called := false
			connector := DirectConnector{DialContext: func(context.Context, string) (net.Conn, error) {
				called = true
				return nil, errors.New("must not dial")
			}}
			_, err := connector.Open(context.Background(), OpenRequest{Host: host, Port: "80", Protocol: "tcp"})
			if err == nil || !strings.Contains(err.Error(), "forbidden") || called {
				t.Fatalf("error=%v called=%v", err, called)
			}
		})
	}
}

func TestRelayConnectorIsUnavailableWithoutFallback(t *testing.T) {
	_, err := (RelayUnavailableConnector{}).Open(context.Background(), OpenRequest{Host: "192.0.2.10", Port: "443", Protocol: "tcp"})
	if err == nil || !strings.Contains(err.Error(), "Agent Egress Unavailable") {
		t.Fatalf("error=%v", err)
	}
}

func TestConnectorConnectionBudgetIsShared(t *testing.T) {
	base := DirectConnector{DialContext: func(_ context.Context, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}}
	connector := &BudgetConnector{Connector: base, Limit: 2}
	for index := 0; index < 2; index++ {
		opened, err := connector.Open(context.Background(), OpenRequest{Host: "192.0.2.10", Port: "443", Protocol: "tcp"})
		if err != nil {
			t.Fatal(err)
		}
		_ = opened.Conn.Close()
	}
	_, err := connector.Open(context.Background(), OpenRequest{Host: "192.0.2.10", Port: "443", Protocol: "tcp"})
	if err == nil || !strings.Contains(err.Error(), "connection budget exceeds 2") {
		t.Fatalf("error=%v", err)
	}
}

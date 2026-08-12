package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSOCKS5ConfigurationValidation(t *testing.T) {
	if _, err := NewSOCKS5Client("socks5://user:password@127.0.0.1:1080"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "http://127.0.0.1:8080", "socks5://127.0.0.1", "socks5://127.0.0.1:1080/path"} {
		if _, err := NewSOCKS5Client(value); err == nil {
			t.Fatalf("expected %q to fail", value)
		}
	}
}

func TestSOCKS5ConnectionErrorDoesNotEchoCredentials(t *testing.T) {
	const secret = "never-echo-this-password"
	client, err := NewSOCKS5Client("socks5://user:" + secret + "@127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.Dial(ctx, "192.0.2.10:443", []string{"tcp://192.0.2.10:443"})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error must not echo credentials: %v", err)
	}
}

func TestSOCKS5ClientSendsPinnedIPToProxy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	targets := make(chan string, 1)
	go serveOneSOCKS5Connect(listener, targets)

	client, err := NewSOCKS5Client("socks5://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.Dial(ctx, "192.0.2.10:443", []string{"tcp://192.0.2.10:443"}); err != nil {
		t.Fatal(err)
	}
	select {
	case target := <-targets:
		if target != "192.0.2.10:443" {
			t.Fatalf("SOCKS5 CONNECT target=%q", target)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestSOCKS5ClientPerformsUsernamePasswordAuthentication(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	authenticated := make(chan string, 1)
	go serveOneAuthenticatedSOCKS5Connect(listener, authenticated)

	client, err := NewSOCKS5Client("socks5://test-user:test-password@" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.Dial(ctx, "192.0.2.10:443", []string{"tcp://192.0.2.10:443"}); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-authenticated:
		if value != "test-user:test-password@192.0.2.10:443" {
			t.Fatalf("handshake=%q", value)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func serveOneAuthenticatedSOCKS5Connect(listener net.Listener, authenticated chan<- string) {
	connection, err := listener.Accept()
	if err != nil {
		return
	}
	defer connection.Close()
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(connection, greeting); err != nil {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(connection, methods); err != nil || !containsByte(methods, 2) {
		return
	}
	if _, err := connection.Write([]byte{5, 2}); err != nil {
		return
	}
	authHeader := make([]byte, 2)
	if _, err := io.ReadFull(connection, authHeader); err != nil || authHeader[0] != 1 {
		return
	}
	username := make([]byte, int(authHeader[1]))
	if _, err := io.ReadFull(connection, username); err != nil {
		return
	}
	passwordLength := make([]byte, 1)
	if _, err := io.ReadFull(connection, passwordLength); err != nil {
		return
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(connection, password); err != nil {
		return
	}
	if _, err := connection.Write([]byte{1, 0}); err != nil {
		return
	}
	target, ok := readSOCKS5Target(connection)
	if !ok {
		return
	}
	authenticated <- string(username) + ":" + string(password) + "@" + target
	_, _ = connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
}

func containsByte(values []byte, wanted byte) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func serveOneSOCKS5Connect(listener net.Listener, targets chan<- string) {
	connection, err := listener.Accept()
	if err != nil {
		return
	}
	defer connection.Close()
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(connection, greeting); err != nil {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return
	}
	if _, err := connection.Write([]byte{5, 0}); err != nil {
		return
	}
	target, ok := readSOCKS5Target(connection)
	if !ok {
		return
	}
	targets <- target
	_, _ = connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
}

func readSOCKS5Target(connection net.Conn) (string, bool) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", false
	}
	var host string
	switch header[3] {
	case 1:
		raw := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(connection, raw); err != nil {
			return "", false
		}
		host = net.IP(raw).String()
	case 4:
		raw := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(connection, raw); err != nil {
			return "", false
		}
		host = net.IP(raw).String()
	default:
		return "", false
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(connection, portBytes); err != nil {
		return "", false
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(portBytes))), true
}

func TestScopedClientFailsClosedAfterClear(t *testing.T) {
	client := &ScopedClient{}
	client.Set(DisabledClient{})
	client.Clear()
	_, err := client.Dial(context.Background(), "example.test:443", []string{"tcp://example.test:443"})
	if err == nil || !strings.Contains(err.Error(), "egress is disabled") {
		t.Fatalf("error=%v", err)
	}
}

type contextProbeClient struct{ seen chan error }

func (c contextProbeClient) HTTPGet(ctx context.Context, _ string, _ []string) (HTTPResult, error) {
	<-ctx.Done()
	c.seen <- ctx.Err()
	return HTTPResult{}, ctx.Err()
}

func (c contextProbeClient) Dial(ctx context.Context, _ string, _ []string) (string, error) {
	<-ctx.Done()
	c.seen <- ctx.Err()
	return "", ctx.Err()
}

func TestScopedClientPropagatesTopLevelCancellation(t *testing.T) {
	runCtx, cancel := context.WithCancel(context.Background())
	seen := make(chan error, 1)
	client := &ScopedClient{}
	client.SetContext(runCtx, contextProbeClient{seen: seen})
	done := make(chan struct{})
	go func() {
		_, _ = client.Dial(context.Background(), "example.test:443", []string{"tcp://example.test:443"})
		close(done)
	}()
	cancel()
	select {
	case err := <-seen:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("top-level cancellation did not reach connector")
	}
	<-done
}

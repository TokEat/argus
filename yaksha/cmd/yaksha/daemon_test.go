package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPersistentDaemonHTTPAndWorkerRecycle(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	command := exec.Command(yakshaBin, "serve")
	command.Env = append(os.Environ(), "YAKSHA_LISTEN_ADDR="+address, "YAKSHA_WORKERS=2", "YAKSHA_QUEUE_SIZE=4", "YAKSHA_RECYCLE_AFTER=2")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	})
	baseURL := "http://" + address
	waitReady(t, baseURL)

	for index := 0; index < 6; index++ {
		response := daemonCall(t, baseURL, map[string]any{"id": "call-" + string(rune('a'+index)), "action": "run", "script": "cli.check(); yaksha.result(42)"})
		if response.Status != "Succeeded" {
			t.Fatalf("call %d: %#v", index, response)
		}
	}
	waitReady(t, baseURL)

	proxyURL, connected := startSOCKS5Stub(t)
	networkScript := `cli.check(); _, err = yaksha.dial("192.0.2.10:443"); yaksha.result(err == nil)`
	proxied := daemonCall(t, baseURL, map[string]any{
		"action": "run", "script": networkScript,
		"network_targets": []string{"tcp://192.0.2.10:443"},
		"egress":          map[string]any{"mode": "socks5", "socks5_proxy": proxyURL},
	})
	if proxied.Status != "Succeeded" || proxied.Result != true {
		t.Fatalf("per-request SOCKS5 call failed: %#v", proxied)
	}
	select {
	case target := <-connected:
		if target != "192.0.2.10:443" {
			t.Fatalf("proxy target=%q", target)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS5 proxy did not receive a CONNECT")
	}
	closed := daemonCall(t, baseURL, map[string]any{"action": "run", "script": networkScript, "network_targets": []string{"tcp://192.0.2.10:443"}})
	if closed.Status != "Succeeded" || closed.Result != false {
		t.Fatalf("missing proxy did not fail closed: %#v", closed)
	}

	inspect := daemonCall(t, baseURL, map[string]any{"action": "inspect", "script": `yaksha.call("child", 1, {})`, "egress": map[string]any{"mode": "direct"}})
	if inspect.Status != "InternalError" {
		t.Fatalf("inspect accepted egress selector: %#v", inspect)
	}
}

func startSOCKS5Stub(t *testing.T) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	connected := make(chan string, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
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
		_, _ = connection.Write([]byte{5, 0})
		header := make([]byte, 4)
		if _, err := io.ReadFull(connection, header); err != nil || header[3] != 1 {
			return
		}
		address := make([]byte, 4)
		port := make([]byte, 2)
		if _, err := io.ReadFull(connection, address); err != nil {
			return
		}
		if _, err := io.ReadFull(connection, port); err != nil {
			return
		}
		connected <- net.JoinHostPort(net.IP(address).String(), fmt.Sprint(binary.BigEndian.Uint16(port)))
		_, _ = connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
	}()
	return "socks5://" + listener.Addr().String(), connected
}

func waitReady(t *testing.T, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(baseURL + "/readyz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("daemon did not become ready")
}

func daemonCall(t *testing.T, baseURL string, value any) wireResponse {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/execute", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var result wireResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode HTTP %d response %q: %v", response.StatusCode, body, err)
	}
	return result
}

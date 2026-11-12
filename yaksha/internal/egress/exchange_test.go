package egress

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPRequestCarriesMethodHeadersBodyAndResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("X-Lab") != "yes" || string(body) != "payload" {
			t.Errorf("unexpected request: %s %q %q", r.Method, r.Header.Get("X-Lab"), body)
		}
		w.Header().Set("X-Result", "ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer server.Close()
	client := NewDirectClient(net.DefaultResolver, true).(ExtendedClient)
	result, err := client.HTTPRequest(context.Background(), HTTPRequest{Method: "POST", URL: server.URL, Headers: map[string]string{"X-Lab": "yes"}, Body: "payload", BodyEncoding: "utf8"}, []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != 201 || result.Body != "created" || result.BodyEncoding != "utf8" || len(result.Headers["X-Result"]) != 1 || result.Headers["X-Result"][0] != "ok" {
		t.Fatalf("result=%+v", result)
	}
}

func TestHTTPRequestRejectsUnsafeInputs(t *testing.T) {
	client := NewDirectClient(net.DefaultResolver, true).(ExtendedClient)
	for _, request := range []HTTPRequest{
		{Method: "CONNECT", URL: "http://127.0.0.1:1"},
		{Method: "GET", URL: "http://127.0.0.1:1", Headers: map[string]string{"Proxy-Authorization": "secret"}},
		{Method: "GET", URL: "http://127.0.0.1:1", Headers: map[string]string{"X-Test": "ok\r\nInjected: yes"}},
	} {
		if _, err := client.HTTPRequest(context.Background(), request, []string{"http://127.0.0.1:1"}); err == nil {
			t.Fatalf("request should be rejected: %+v", request)
		}
	}
}

func TestTCPExchangePreservesOrderedSteps(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString('\n')
		if line == "hello\n" {
			_, _ = conn.Write([]byte("world\n"))
		}
	}()
	address := listener.Addr().String()
	client := NewDirectClient(net.DefaultResolver, true).(ExtendedClient)
	result, err := client.TCPExchange(context.Background(), TCPExchangeRequest{Address: address, Steps: []TCPStep{{Operation: "write", Data: "hello\n"}, {Operation: "read", Until: "\n", MaxBytes: 64, IdleTimeoutMS: 1000}, {Operation: "half_close"}}}, []string{"tcp://" + address})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Responses, "") != "world\n" {
		t.Fatalf("result=%+v", result)
	}
}

package mcp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func startYakshaDaemon(t *testing.T, binary string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	command := exec.Command(binary, "serve")
	command.Env = append(os.Environ(), "YAKSHA_LISTEN_ADDR="+address, "YAKSHA_WORKERS=2", "YAKSHA_QUEUE_SIZE=4", "YAKSHA_RECYCLE_AFTER=5")
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
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		response, requestErr := http.Get(baseURL + "/readyz")
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return baseURL
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("Yaksha daemon did not become ready")
	return ""
}

// This opt-in acceptance test proves MCP calls a persistent Yaksha daemon over
// HTTP. Network execution is covered separately with an explicit SOCKS5 test
// proxy; this loop intentionally remains offline.
func TestMCPToRealYakshaVerticalLoop(t *testing.T) {
	binary := strings.TrimSpace(os.Getenv("ARGUS_YAKSHA_TEST_BIN"))
	if binary == "" {
		t.Skip("set ARGUS_YAKSHA_TEST_BIN to run the real MCP -> Yaksha daemon acceptance test")
	}
	baseURL := startYakshaDaemon(t, binary)
	client := NewClientWithYakshaURL("", "", baseURL)
	session, cleanup := connectTestSession(t, NewServer(client))
	defer cleanup()

	call := func(action, script string, extra map[string]interface{}) map[string]interface{} {
		t.Helper()
		arguments := map[string]interface{}{"action": action, "script": script, "timeout_ms": 15000}
		for key, value := range extra {
			arguments[key] = value
		}
		result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: "argus_yaksha_exp", Arguments: arguments})
		if err != nil || result.IsError {
			t.Fatalf("%s result=%#v err=%v", action, result, err)
		}
		structured, ok := result.StructuredContent.(map[string]interface{})
		if !ok || structured["status"] != "Succeeded" {
			t.Fatalf("%s structuredContent=%#v", action, result.StructuredContent)
		}
		return structured
	}

	const simple = `name = cli.String("name", cli.setRequired(true)); cli.check(); yaksha.result({"hello": name})`
	inspect := call("inspect", simple, nil)
	inspection := inspect["inspection"].(map[string]interface{})
	if inspection["valid"] != true {
		t.Fatalf("inspection=%#v", inspection)
	}
	params := map[string]interface{}{"params": map[string]interface{}{"name": "yaksha"}, "dependencies": []interface{}{}, "assets": []interface{}{}, "network_targets": []interface{}{}}
	call("validate", simple, params)
	run := call("run", simple, params)
	raw, _ := json.Marshal(run)
	if !strings.Contains(string(raw), `"hello":"yaksha"`) {
		t.Fatalf("run=%s", raw)
	}
	call("debug", simple, params)
	call("test", simple, map[string]interface{}{"dependencies": []interface{}{}, "assets": []interface{}{}, "network_targets": []interface{}{}, "test_cases": []interface{}{map[string]interface{}{"id": "simple", "params": map[string]interface{}{"name": "yaksha"}, "expect": map[string]interface{}{"result": map[string]interface{}{"hello": "yaksha"}}}}})
}

func TestArgusMCPProcessCallsRealYaksha(t *testing.T) {
	mcpBinary := strings.TrimSpace(os.Getenv("ARGUS_MCP_TEST_BIN"))
	yakshaBinary := strings.TrimSpace(os.Getenv("ARGUS_YAKSHA_TEST_BIN"))
	if mcpBinary == "" || yakshaBinary == "" {
		t.Skip("set ARGUS_MCP_TEST_BIN and ARGUS_YAKSHA_TEST_BIN for process acceptance")
	}
	yakshaURL := startYakshaDaemon(t, yakshaBinary)
	command := exec.Command(mcpBinary)
	command.Env = append(os.Environ(), "ARGUS_MCP_TRANSPORT=stdio", "ARGUS_YAKSHA_URL="+yakshaURL, "ARGUS_BASE_URL=", "ARGUS_TOKEN=", "ARGUS_TOKEN_FILE=")
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "argus-mcp-process-acceptance", Version: "0.1.0"}, nil)
	session, err := client.Connect(context.Background(), &sdkmcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: "argus_yaksha_exp", Arguments: map[string]interface{}{"action": "inspect", "script": `target = cli.String("target", cli.setRequired(true)); cli.check()`}})
	if err != nil || result.IsError || result.StructuredContent == nil {
		t.Fatalf("process result=%#v err=%v", result, err)
	}
	resource, err := session.ReadResource(context.Background(), &sdkmcp.ReadResourceParams{URI: expConsoleURI})
	if err != nil || len(resource.Contents) == 0 {
		t.Fatalf("read EXP console: %v", err)
	}
	data, _ := json.Marshal(resource.Contents)
	if !strings.Contains(string(data), expConsoleMIMEType) {
		t.Fatalf("unexpected EXP console: %s", data)
	}
}

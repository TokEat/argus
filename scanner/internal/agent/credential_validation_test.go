package agent

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestWorkerTLSAndCredentialValidationFailClosed(t *testing.T) {
	worker := NewWorker("agent-tls", "127.0.0.1:50053", "http://127.0.0.1:8085", 1, nil)
	cfg := engine.Config(structs.DefaultConfig())
	cfg.ExecutionMode = "credential_validation"
	if err := worker.prepareCredentialValidationConfig(&cfg, "attempt-a"); err == nil || !strings.Contains(err.Error(), "CA-verified") {
		t.Fatalf("plaintext credential validation error=%v", err)
	}

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	certificate := tlsServer.TLS.Certificates[0].Certificate[0]
	caFile := filepath.Join(t.TempDir(), "agent-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := worker.SetTLS(caFile, "example.test"); err != nil {
		t.Fatalf("SetTLS: %v", err)
	}
	if !worker.transportTLS || worker.transportCredentials == nil {
		t.Fatal("SetTLS did not activate verified transport credentials")
	}

	cfg.CredentialBundleRef = "sealed-ref"
	cfg.CredentialBundleCount = 1
	cfg.CredentialBundleSHA256, _ = credentialBundleDigest([]structs.UserPasswd{{UserName: "incremental-user", Password: "incremental-password"}})
	if err := worker.prepareCredentialValidationConfig(&cfg, "attempt-a"); err == nil || !strings.Contains(err.Error(), "provider is unavailable") {
		t.Fatalf("missing bundle provider error=%v", err)
	}
	worker.credentialBundleProvider = func(ctx context.Context, taskID, ref string) ([]structs.UserPasswd, error) {
		if taskID != "attempt-a" || ref != "sealed-ref" {
			t.Fatalf("unexpected bundle request task=%q ref=%q", taskID, ref)
		}
		return []structs.UserPasswd{{UserName: "incremental-user", Password: "incremental-password"}}, nil
	}
	if err := worker.prepareCredentialValidationConfig(&cfg, "attempt-a"); err != nil {
		t.Fatalf("prepare credential config: %v", err)
	}
	if len(cfg.CredentialBundle) != 1 {
		t.Fatalf("credential bundle count=%d, want 1", len(cfg.CredentialBundle))
	}
}

func TestCredentialFindingIsNeverMirroredToAgentLogs(t *testing.T) {
	if shouldMirrorAgentOutputForMode("GoPoc", "credential_validation") {
		t.Fatal("credential finding would be mirrored to the Agent console log")
	}
	if !shouldMirrorAgentOutputForMode("GoPoc", "") {
		t.Fatal("legacy non-credential GoPoc console behavior changed")
	}
}

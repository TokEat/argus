package grpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/credentialvault"
	"github.com/TokEat/argus/server/internal/db"
	pb "github.com/TokEat/argus/shared/proto/go/scan"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func credentialTLSContext(token string) context.Context {
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{Version: tls.VersionTLS13}}})
	return metadata.NewIncomingContext(ctx, metadata.Pairs("x-agent-token", token))
}

func TestSealedNucleiBudgetExceededIsNotAutomaticallyRetried(t *testing.T) {
	if !isSealedNucleiBudgetExceeded("run Nuclei enumeration: nuclei request budget exceeded") {
		t.Fatal("budget exhaustion must be recognized")
	}
	if isSealedNucleiBudgetExceeded("phase_failed") {
		t.Fatal("unrelated failures must still auto-retry")
	}
}

func TestFetchCredentialBundleIsTLSBoundAndOneTime(t *testing.T) {
	store := setupRegisterTestDB(t)
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	tenantID, projectID, agentID, token, taskID, ref := "tenant-credential", "project-credential", "agent-credential", "token-credential", "attempt-credential", "bundle-credential"
	if err := store.Create(&db.Node{TenantID: tenantID, AgentID: agentID, Status: "Alive", Token: token, TokenExpiresAt: &expires}).Error; err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`[{"username":"admin","password":"incremental-secret"}]`)
	vault, _ := credentialvault.NewFromEnvironment(true)
	ciphertext, nonce, err := vault.Seal(plaintext, []byte("bundle:"+tenantID+":"+taskID+":"+ref))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plaintext)
	config, _ := json.Marshal(map[string]interface{}{"ExecutionMode": "credential_validation", "CredentialBundleRef": ref, "CredentialBundleSHA256": hex.EncodeToString(sum[:]), "CredentialBundleCount": 1})
	if err := store.Create(&db.SubTask{ID: taskID, TenantID: tenantID, ProjectID: projectID, AgentID: agentID, Status: "Running", Config: string(config)}).Error; err != nil {
		t.Fatal(err)
	}
	bundle := db.CredentialBundle{Ref: ref, TenantID: tenantID, ProjectID: projectID, AttemptID: taskID, SHA256: hex.EncodeToString(sum[:]), PairCount: 1, Ciphertext: ciphertext, Nonce: nonce, ExpiresAt: expires}
	if err := store.Create(&bundle).Error; err != nil {
		t.Fatal(err)
	}
	server := NewServer(50051)
	request := &pb.FetchCredentialBundleReq{AgentId: agentID, TaskId: taskID, BundleRef: ref}
	if _, err := server.FetchCredentialBundle(metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-agent-token", token)), request); err == nil || !strings.Contains(err.Error(), "CA-verified") {
		t.Fatalf("plaintext bundle fetch error=%v", err)
	}
	response, err := server.FetchCredentialBundle(credentialTLSContext(token), request)
	if err != nil {
		t.Fatalf("fetch bundle: %v", err)
	}
	if response.PairCount != 1 || len(response.Pairs) != 1 || response.Pairs[0].Username != "admin" || response.Pairs[0].Password != "incremental-secret" {
		t.Fatalf("unexpected bundle response: %+v", response)
	}
	if _, err := server.FetchCredentialBundle(credentialTLSContext(token), request); err == nil || !strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("second fetch error=%v", err)
	}
}

func TestCredentialResultSealsEvidenceAndRejectsSideChannels(t *testing.T) {
	store := setupRegisterTestDB(t)
	expires := time.Now().Add(time.Hour)
	tenantID, projectID, rootID, agentID, token, taskID := "tenant-result", "project-result", "root-result", "agent-result", "token-result", "attempt-result"
	if err := store.Create(&db.Node{TenantID: tenantID, AgentID: agentID, Status: "Alive", Token: token, TokenExpiresAt: &expires}).Error; err != nil {
		t.Fatal(err)
	}
	config := `{"ExecutionMode":"credential_validation","CredentialValidationTargets":[{"endpoint":"192.0.2.10:22","service":"ssh","plugin":"SSH-Crack"}]}`
	if err := store.Create(&db.SubTask{ID: taskID, TenantID: tenantID, ProjectID: projectID, RootTaskID: rootID, AgentID: agentID, Status: "Running", Config: config}).Error; err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"go_poc":{"poc_name":"SSH-Login","security":"CRITICAL","target":"192.0.2.10:22","info_left":"Username: admin\nPassword: verified-secret","info_right":"private shell output","show_msg":"ssh://admin:verified-secret@192.0.2.10","exchanges":[{"request":"verified-secret","response":"private"}]}}`)
	handled, err := persistCredentialValidationResult(credentialTLSContext(token), &pb.ScanResult{TaskId: taskID, PayloadType: "GoPoc", Payload: payload})
	if !handled || err != nil {
		t.Fatalf("persist credential result handled=%v err=%v", handled, err)
	}
	var finding db.CredentialFindingSecret
	if err := store.Where("attempt_id = ?", taskID).First(&finding).Error; err != nil {
		t.Fatal(err)
	}
	if finding.Service != "ssh" || finding.Plugin != "SSH-Crack" || finding.MaskedUsername != "a***n" || bytes.Contains(finding.Ciphertext, []byte("verified-secret")) {
		t.Fatalf("unsafe credential finding: %+v", finding)
	}
	vault, _ := credentialvault.NewFromEnvironment(true)
	plaintext, err := vault.Open(finding.Ciphertext, finding.Nonce, []byte("finding:"+tenantID+":"+finding.ID))
	if err != nil || !bytes.Contains(plaintext, []byte("verified-secret")) || !bytes.Contains(plaintext, []byte("private shell output")) {
		t.Fatalf("sealed evidence missing: %s err=%v", plaintext, err)
	}
	if handled, err := persistCredentialValidationResult(credentialTLSContext(token), &pb.ScanResult{TaskId: taskID, PayloadType: "arbitrary", Payload: []byte(`{"password":"bypass"}`)}); !handled || err == nil {
		t.Fatalf("unexpected side-channel result handled=%v err=%v", handled, err)
	}
	unknownTarget := []byte(`{"go_poc":{"poc_name":"SSH-Login","security":"CRITICAL","target":"192.0.2.99:22","info_left":"Username: admin\nPassword: rejected"}}`)
	if handled, err := persistCredentialValidationResult(credentialTLSContext(token), &pb.ScanResult{TaskId: taskID, PayloadType: "GoPoc", Payload: unknownTarget}); !handled || err == nil || !strings.Contains(err.Error(), "sealed attempt plan") {
		t.Fatalf("unknown endpoint handled=%v err=%v", handled, err)
	}
	missingCredentials := []byte(`{"go_poc":{"poc_name":"SSH-Login","security":"CRITICAL","target":"192.0.2.10:22","info_left":"authentication succeeded"}}`)
	if handled, err := persistCredentialValidationResult(credentialTLSContext(token), &pb.ScanResult{TaskId: taskID, PayloadType: "GoPoc", Payload: missingCredentials}); !handled || err == nil || !strings.Contains(err.Error(), "structured credential evidence") {
		t.Fatalf("missing credential evidence handled=%v err=%v", handled, err)
	}
	if value, present := credentialPatternValue(credentialPasswordPattern, "Password: <empty>"); !present || value != "" {
		t.Fatalf("explicit empty password was not normalized: value=%q present=%v", value, present)
	}
}

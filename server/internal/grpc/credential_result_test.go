package grpc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/credentialvault"
	"github.com/TokEat/argus/server/internal/db"
	pb "github.com/TokEat/argus/shared/proto/go/scan"
)

func TestCredentialFindingIDDeterministic(t *testing.T) {
	base := credentialFindingID("tenant-a", "project-a", "192.0.2.10:22", "admin")

	if again := credentialFindingID("tenant-a", "project-a", "192.0.2.10:22", "admin"); again != base {
		t.Fatalf("same input must yield same id: %q vs %q", again, base)
	}
	// 用户名大小写不敏感，避免 Admin/admin 漂移成两行。
	if got := credentialFindingID("tenant-a", "project-a", "192.0.2.10:22", "Admin"); got != base {
		t.Fatalf("username must be case-insensitive: %q vs %q", got, base)
	}
	for _, tc := range []struct{ tenant, project, endpoint, user string }{
		{"tenant-b", "project-a", "192.0.2.10:22", "admin"},
		{"tenant-a", "project-b", "192.0.2.10:22", "admin"},
		{"tenant-a", "project-a", "192.0.2.10:23", "admin"},
		{"tenant-a", "project-a", "192.0.2.10:22", "root"},
	} {
		if got := credentialFindingID(tc.tenant, tc.project, tc.endpoint, tc.user); got == base {
			t.Fatalf("(%s,%s,%s,%s) must differ from base id", tc.tenant, tc.project, tc.endpoint, tc.user)
		}
	}
}

func TestPersistCredentialResultDeduplicatesByEndpointAndUsername(t *testing.T) {
	store := setupRegisterTestDB(t)
	expires := time.Now().Add(time.Hour)
	tenantID, projectID := "tenant-dedupe", "project-dedupe"
	token := "token-dedupe"

	// 两个不同 attempt（模拟两次扫描各自派生的凭据验证批），同一端点。
	config := `{"ExecutionMode":"credential_validation","CredentialValidationTargets":[{"endpoint":"192.0.2.10:22","service":"ssh","plugin":"SSH-Crack"}]}`
	for _, id := range []string{"attempt-dedupe-1", "attempt-dedupe-2"} {
		agentID := "agent-" + id
		if err := store.Create(&db.Node{TenantID: tenantID, AgentID: agentID, Status: "Alive", Token: token, TokenExpiresAt: &expires}).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.Create(&db.SubTask{ID: id, TenantID: tenantID, ProjectID: projectID, RootTaskID: "root-" + id, AgentID: agentID, Status: "Running", Config: config}).Error; err != nil {
			t.Fatal(err)
		}
	}

	persist := func(taskID, infoLeft string) {
		t.Helper()
		payload, err := json.Marshal(map[string]interface{}{
			"go_poc": map[string]interface{}{
				"poc_name": "SSH-Login",
				"security": "CRITICAL",
				"target":   "192.0.2.10:22",
				"info_left": infoLeft,
				"show_msg":  "ssh://192.0.2.10:22",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		handled, err := persistCredentialValidationResult(credentialTLSContext(token), &pb.ScanResult{TaskId: taskID, PayloadType: "GoPoc", Payload: payload})
		if !handled || err != nil {
			t.Fatalf("persist handled=%v err=%v", handled, err)
		}
	}
	count := func() int64 {
		t.Helper()
		var n int64
		if err := store.Model(&db.CredentialFindingSecret{}).Where("endpoint = ?", "192.0.2.10:22").Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		return n
	}

	// 第一次：admin / pw-first。
	persist("attempt-dedupe-1", "Username: admin\nPassword: pw-first")
	if count() != 1 {
		t.Fatalf("expected 1 finding after first persist, got %d", count())
	}
	var first db.CredentialFindingSecret
	if err := store.Where("endpoint = ?", "192.0.2.10:22").First(&first).Error; err != nil {
		t.Fatal(err)
	}

	// 第二次：同端点同账号、不同 attempt、不同密码 → 仍一行，密码更新为最新。
	persist("attempt-dedupe-2", "Username: admin\nPassword: pw-second")
	if count() != 1 {
		t.Fatalf("re-validation must collapse to one row, got %d", count())
	}
	var updated db.CredentialFindingSecret
	if err := store.Where("endpoint = ?", "192.0.2.10:22").First(&updated).Error; err != nil {
		t.Fatal(err)
	}
	if updated.AttemptID != "attempt-dedupe-2" {
		t.Fatalf("attempt_id should point to latest validation, got %q", updated.AttemptID)
	}
	if !updated.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("created_at must stay first-seen: %v vs %v", updated.CreatedAt, first.CreatedAt)
	}
	vault, _ := credentialvault.NewFromEnvironment(true)
	plaintext, err := vault.Open(updated.Ciphertext, updated.Nonce, []byte("finding:"+tenantID+":"+updated.ID))
	if err != nil {
		t.Fatalf("reveal after dedupe: %v", err)
	}
	if !strings.Contains(string(plaintext), "pw-second") || strings.Contains(string(plaintext), "pw-first") {
		t.Fatalf("secret must be refreshed to latest password, got %s", plaintext)
	}

	// 换一个用户名 root → 第二行。
	persist("attempt-dedupe-2", "Username: root\nPassword: rootpw")
	if count() != 2 {
		t.Fatalf("a different account must add a row, got %d", count())
	}
}

package credentialbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/credentialvault"
	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAppendRetryIssuesFreshAttemptBoundBundle(t *testing.T) {
	store, err := gorm.Open(sqlite.Open("file:credential-bundle-retry?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(
		&db.RootTask{}, &db.TaskBatch{}, &db.SubTask{}, &db.ScanPolicyIntent{}, &db.ScanStageDerivation{},
		&db.CredentialDictionary{}, &db.CredentialDictionaryRevision{}, &db.CredentialBundle{},
	); err != nil {
		t.Fatal(err)
	}
	root := db.RootTask{ID: "root-retry", TenantID: "tenant-retry", ProjectID: "project-retry", Status: "Running", TimeoutSec: 3600}
	batch := db.TaskBatch{ID: "batch-retry", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Kind: "credential_validation", Status: "Running", ControlState: string(db.BatchControlActive), CurrentAttemptNo: 1, AttemptCount: 1, LatestAttemptID: "attempt-retry-1"}
	previous := db.SubTask{ID: batch.LatestAttemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, AttemptNo: 1, Status: "Running", Config: `{"ExecutionMode":"credential_validation"}`, MaxRetry: 1, TimeoutSec: 3600}

	vault, err := credentialvault.NewFromEnvironment(true)
	if err != nil {
		t.Fatal(err)
	}
	sealRevision := func(dictionary db.CredentialDictionary, values []string) db.CredentialDictionaryRevision {
		t.Helper()
		plaintext, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, nonce, err := vault.Seal(plaintext, []byte("dictionary:"+root.TenantID+":"+root.ProjectID+":"+dictionary.ID+":1"))
		if err != nil {
			t.Fatal(err)
		}
		return db.CredentialDictionaryRevision{TenantID: root.TenantID, ProjectID: root.ProjectID, DictionaryID: dictionary.ID, Revision: 1, SHA256: sha256Hex(plaintext), ItemCount: len(values), Ciphertext: ciphertext, Nonce: nonce, CreatedBy: "operator"}
	}
	users := db.CredentialDictionary{ID: "users-retry", TenantID: root.TenantID, ProjectID: root.ProjectID, Kind: "username", Name: "users", CreatedBy: "operator"}
	passwords := db.CredentialDictionary{ID: "passwords-retry", TenantID: root.TenantID, ProjectID: root.ProjectID, Kind: "password", Name: "passwords", CreatedBy: "operator"}
	userRevision := sealRevision(users, []string{"admin"})
	passwordRevision := sealRevision(passwords, []string{"incremental"})
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetQuick)
	policy.Capabilities.CredentialValidation = true
	policy.Authorization.ValidationConfirmed = true
	policy.Credentials.UsernameBooks = []scanpolicy.DictionaryRef{{ID: users.ID, Revision: 1, SHA256: userRevision.SHA256, Count: 1}}
	policy.Credentials.PasswordBooks = []scanpolicy.DictionaryRef{{ID: passwords.ID, Revision: 1, SHA256: passwordRevision.SHA256, Count: 1}}
	policyJSON, _ := json.Marshal(policy)
	intent := db.ScanPolicyIntent{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, PolicyJSON: string(policyJSON)}
	original, err := Seal(root, batch.ID, previous.ID, []Pair{{UserName: "admin", Password: "incremental"}})
	if err != nil {
		t.Fatal(err)
	}
	previous.Config = `{"ExecutionMode":"credential_validation","CredentialBundleRef":"` + original.Ref + `","CredentialBundleSHA256":"` + original.SHA256 + `","CredentialBundleCount":1}`
	for _, row := range []interface{}{&root, &batch, &previous, &users, &passwords, &userRevision, &passwordRevision, &intent, &original} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	prepared, appended, err := AppendRetry(store, &previous, db.AttemptRetryOptions{
		Trigger: db.AttemptTriggerTimeoutRetry, TerminalStatus: "Timeout", FailureReason: "deadline",
		ConsumeRetryBudget: true, PreserveRuleVersion: true,
	})
	if err != nil || !appended {
		t.Fatalf("append credential retry appended=%v err=%v", appended, err)
	}
	var contract struct {
		CredentialBundleRef    string
		CredentialBundleSHA256 string
		CredentialBundleCount  int
	}
	if err := json.Unmarshal([]byte(prepared.Config), &contract); err != nil {
		t.Fatal(err)
	}
	if contract.CredentialBundleRef == "" || contract.CredentialBundleRef == original.Ref || contract.CredentialBundleCount != 1 {
		t.Fatalf("retry did not receive a fresh bundle: %+v", contract)
	}
	var replacement db.CredentialBundle
	if err := store.Where("ref = ? AND attempt_id = ?", contract.CredentialBundleRef, prepared.ID).First(&replacement).Error; err != nil {
		t.Fatal(err)
	}
	var retired db.CredentialBundle
	if err := store.Where("ref = ?", original.Ref).First(&retired).Error; err != nil {
		t.Fatal(err)
	}
	if retired.ExpiresAt.After(time.Now().UTC().Add(time.Second)) {
		t.Fatalf("superseded capability remains live until %s", retired.ExpiresAt)
	}
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

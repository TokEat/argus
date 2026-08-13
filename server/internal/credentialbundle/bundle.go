package credentialbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/credentialvault"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Pair struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

func LoadCustomPairs(tx *gorm.DB, policy scanpolicy.Policy, tenantID, projectID string, limit int) ([]Pair, error) {
	usernames, err := loadDictionaryValues(tx, tenantID, projectID, "username", policy.Credentials.UsernameBooks)
	if err != nil {
		return nil, err
	}
	passwords, err := loadDictionaryValues(tx, tenantID, projectID, "password", policy.Credentials.PasswordBooks)
	if err != nil {
		return nil, err
	}
	if len(usernames) == 0 || len(passwords) == 0 {
		return nil, nil
	}
	pairCount, err := CheckedPairCount(len(usernames), len(passwords), limit)
	if err != nil {
		return nil, err
	}
	pairs := make([]Pair, 0, pairCount)
	for _, username := range usernames {
		for _, password := range passwords {
			pairs = append(pairs, Pair{UserName: username, Password: password})
		}
	}
	return pairs, nil
}

func CheckedPairCount(usernames, passwords, limit int) (int, error) {
	if usernames == 0 || passwords == 0 {
		return 0, nil
	}
	pairs := int64(usernames) * int64(passwords)
	if limit < 1 || pairs > int64(limit) {
		return 0, fmt.Errorf("custom dictionary cartesian product %d exceeds per-service limit %d", pairs, limit)
	}
	return int(pairs), nil
}

func loadDictionaryValues(tx *gorm.DB, tenantID, projectID, kind string, refs []scanpolicy.DictionaryRef) ([]string, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	vault, err := credentialvault.NewFromEnvironment(true)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, ref := range refs {
		var revision db.CredentialDictionaryRevision
		err := tx.Table("credential_dictionary_revisions AS r").Select("r.*").
			Joins("JOIN credential_dictionaries d ON d.id = r.dictionary_id AND d.tenant_id = r.tenant_id AND d.project_id = r.project_id").
			Where("r.tenant_id = ? AND r.project_id = ? AND r.dictionary_id = ? AND r.revision = ? AND r.sha256 = ? AND r.item_count = ? AND d.kind = ?", tenantID, projectID, ref.ID, ref.Revision, ref.SHA256, ref.Count, kind).
			First(&revision).Error
		if err != nil {
			return nil, fmt.Errorf("sealed dictionary %s revision %d is unavailable", ref.ID, ref.Revision)
		}
		aad := []byte(fmt.Sprintf("dictionary:%s:%s:%s:%d", tenantID, projectID, ref.ID, ref.Revision))
		plaintext, err := vault.Open(revision.Ciphertext, revision.Nonce, aad)
		if err != nil {
			return nil, err
		}
		if sum := sha256.Sum256(plaintext); !strings.EqualFold(hex.EncodeToString(sum[:]), revision.SHA256) {
			return nil, fmt.Errorf("sealed dictionary %s revision %d hash mismatch", ref.ID, ref.Revision)
		}
		var values []string
		if err := json.Unmarshal(plaintext, &values); err != nil {
			return nil, err
		}
		if len(values) != revision.ItemCount {
			return nil, fmt.Errorf("sealed dictionary %s revision %d count mismatch", ref.ID, ref.Revision)
		}
		for _, value := range values {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func Seal(root db.RootTask, batchID, attemptID string, pairs []Pair) (db.CredentialBundle, error) {
	vault, err := credentialvault.NewFromEnvironment(true)
	if err != nil {
		return db.CredentialBundle{}, err
	}
	plaintext, err := json.Marshal(pairs)
	if err != nil {
		return db.CredentialBundle{}, err
	}
	sum := sha256.Sum256(plaintext)
	ref := uuid.NewString()
	ciphertext, nonce, err := vault.Seal(plaintext, []byte("bundle:"+root.TenantID+":"+attemptID+":"+ref))
	if err != nil {
		return db.CredentialBundle{}, err
	}
	bundleTTL := time.Duration(root.TimeoutSec) * time.Second
	if bundleTTL < 15*time.Minute {
		bundleTTL = 15 * time.Minute
	}
	if bundleTTL > 2*time.Hour {
		bundleTTL = 2 * time.Hour
	}
	return db.CredentialBundle{
		Ref: ref, TenantID: root.TenantID, ProjectID: root.ProjectID,
		RootTaskID: root.ID, BatchID: batchID, AttemptID: attemptID,
		SHA256: hex.EncodeToString(sum[:]), PairCount: len(pairs),
		Ciphertext: ciphertext, Nonce: nonce, ExpiresAt: time.Now().UTC().Add(bundleTTL),
	}, nil
}

// ReissueForAttempt rebuilds custom pairs from immutable dictionary Revisions.
// It never copies or reactivates an already consumed capability.
func ReissueForAttempt(tx *gorm.DB, root db.RootTask, batch db.TaskBatch, previous db.SubTask, next *db.SubTask) error {
	if tx == nil || next == nil || strings.TrimSpace(next.ID) == "" {
		return fmt.Errorf("credential retry attempt is missing")
	}
	var intent db.ScanPolicyIntent
	if err := tx.Where("tenant_id = ? AND root_task_id = ?", root.TenantID, root.ID).First(&intent).Error; err != nil {
		return err
	}
	var policy scanpolicy.Policy
	if err := json.Unmarshal([]byte(intent.PolicyJSON), &policy); err != nil {
		return err
	}
	pairs, err := LoadCustomPairs(tx, policy, root.TenantID, root.ProjectID, policy.Credentials.PairLimit)
	if err != nil {
		return err
	}
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(next.Config), &config); err != nil {
		return err
	}
	delete(config, "CredentialBundleRef")
	delete(config, "CredentialBundleSHA256")
	delete(config, "CredentialBundleCount")
	if len(pairs) > 0 {
		bundle, err := Seal(root, batch.ID, next.ID, pairs)
		if err != nil {
			return err
		}
		if err := tx.Create(&bundle).Error; err != nil {
			return err
		}
		config["CredentialBundleRef"] = bundle.Ref
		config["CredentialBundleSHA256"] = bundle.SHA256
		config["CredentialBundleCount"] = bundle.PairCount
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return err
	}
	next.Config = string(encoded)
	if err := tx.Model(&db.SubTask{}).Where("id = ? AND tenant_id = ?", next.ID, next.TenantID).Update("config", next.Config).Error; err != nil {
		return err
	}
	// An unconsumed capability from a superseded Attempt must not remain live.
	return tx.Model(&db.CredentialBundle{}).
		Where("tenant_id = ? AND attempt_id = ? AND consumed_at IS NULL", previous.TenantID, previous.ID).
		Update("expires_at", time.Now().UTC()).Error
}

func AppendRetry(store *gorm.DB, expected *db.SubTask, options db.AttemptRetryOptions) (db.SubTask, bool, error) {
	if store == nil {
		return db.SubTask{}, false, fmt.Errorf("database is unavailable")
	}
	var prepared db.SubTask
	var appended bool
	err := store.Transaction(func(tx *gorm.DB) error {
		var execution struct{ ExecutionMode string }
		_ = json.Unmarshal([]byte(expected.Config), &execution)
		switch strings.ToLower(strings.TrimSpace(execution.ExecutionMode)) {
		case "credential_validation", "risk_validation":
			// Validation Attempts are immutable derived snapshots. A recovery must
			// not replace them with the Root's asset-discovery configuration.
			options.UseCurrentTaskConfig = false
			options.PreserveRuleVersion = true
		}
		var err error
		prepared, appended, err = db.AppendSubTaskAttemptTx(tx, expected, options)
		if err != nil || !appended {
			return err
		}
		var batch db.TaskBatch
		if err := tx.Where("id = ? AND tenant_id = ?", prepared.BatchID, prepared.TenantID).First(&batch).Error; err != nil {
			return err
		}
		kind := strings.ToLower(strings.TrimSpace(batch.Kind))
		if kind != "credential_validation" && kind != "risk_validation" {
			return nil
		}
		var root db.RootTask
		if err := tx.Where("id = ? AND tenant_id = ?", prepared.RootTaskID, prepared.TenantID).First(&root).Error; err != nil {
			return err
		}
		if kind == "credential_validation" {
			if err := ReissueForAttempt(tx, root, batch, *expected, &prepared); err != nil {
				return err
			}
		}
		return db.MarkAutomaticValidationStageDerived(tx, root, batch, prepared.ID)
	})
	return prepared, appended, err
}

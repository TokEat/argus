package subdomaindictionary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
	"gorm.io/gorm"
)

// LoadValues resolves a policy's immutable project-scoped revisions. ActiveOnly
// is used when accepting a new policy; execution deliberately permits a
// subsequently soft-deleted dictionary so existing task snapshots remain valid.
func LoadValues(tx *gorm.DB, policy scanpolicy.Policy, tenantID, projectID string, activeOnly bool) ([]string, error) {
	if len(policy.Subdomains.Wordlists) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{})
	for _, ref := range policy.Subdomains.Wordlists {
		var revision db.SubdomainDictionaryRevision
		query := tx.Table("subdomain_dictionary_revisions AS r").Select("r.*").
			Joins("JOIN subdomain_dictionaries d ON d.id = r.dictionary_id AND d.tenant_id = r.tenant_id AND d.project_id = r.project_id").
			Where("r.tenant_id = ? AND r.project_id = ? AND r.dictionary_id = ? AND r.revision = ?", tenantID, projectID, ref.ID, ref.Revision)
		if activeOnly {
			query = query.Where("d.deleted_at IS NULL")
		}
		if err := query.First(&revision).Error; err != nil {
			return nil, fmt.Errorf("subdomain dictionary %s revision %d is unavailable", ref.ID, ref.Revision)
		}
		if !strings.EqualFold(revision.SHA256, ref.SHA256) || revision.ItemCount != ref.Count {
			return nil, fmt.Errorf("subdomain dictionary %s revision %d metadata changed", ref.ID, ref.Revision)
		}
		encoded := []byte(revision.ValuesJSON)
		if sum := sha256.Sum256(encoded); !strings.EqualFold(hex.EncodeToString(sum[:]), revision.SHA256) {
			return nil, fmt.Errorf("subdomain dictionary %s revision %d hash mismatch", ref.ID, ref.Revision)
		}
		var values []string
		if err := json.Unmarshal(encoded, &values); err != nil {
			return nil, fmt.Errorf("decode subdomain dictionary %s revision %d: %w", ref.ID, ref.Revision, err)
		}
		if len(values) != revision.ItemCount {
			return nil, fmt.Errorf("subdomain dictionary %s revision %d count mismatch", ref.ID, ref.Revision)
		}
		for _, value := range values {
			seen[value] = struct{}{}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values, nil
}

func WithValues(config []byte, values []string) ([]byte, error) {
	if len(values) == 0 {
		return config, nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(config, &payload); err != nil {
		return nil, fmt.Errorf("decode task config for subdomain dictionary: %w", err)
	}
	payload["SubdomainDictionaryWords"] = append([]string(nil), values...)
	return json.Marshal(payload)
}

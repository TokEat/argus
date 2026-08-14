package expworkspace

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

//go:embed labseeds/*.yak
var labSeedSources embed.FS

type LabSeedResult struct {
	Name         string `json:"name"`
	ExpID        string `json:"exp_id"`
	Revision     int    `json:"revision"`
	SourceSHA256 string `json:"source_sha256"`
	Reused       bool   `json:"reused"`
}

type labSeedDefinition struct {
	Name        string
	Description string
	RiskLevel   string
	SourceFile  string
	TestCase    TestCaseInput
}

func DevelopmentLabSeedSources() map[string]string {
	result := map[string]string{}
	for _, definition := range developmentLabSeeds() {
		raw, err := labSeedSources.ReadFile("labseeds/" + definition.SourceFile)
		if err == nil {
			result[definition.Name] = string(raw)
		}
	}
	return result
}

func (s *Service) SeedDevelopmentLab(ctx context.Context, tenantID, actorID string) ([]LabSeedResult, error) {
	tenantID, actorID = strings.TrimSpace(tenantID), strings.TrimSpace(actorID)
	if tenantID == "" || actorID == "" {
		return nil, errors.New("development EXP lab tenant and actor are required")
	}
	results := make([]LabSeedResult, 0, len(developmentLabSeeds()))
	for _, definition := range developmentLabSeeds() {
		result, err := s.seedDevelopmentLabEXP(ctx, tenantID, actorID, definition)
		if err != nil {
			return nil, fmt.Errorf("seed %s: %w", definition.Name, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func (s *Service) seedDevelopmentLabEXP(ctx context.Context, tenantID, actorID string, definition labSeedDefinition) (LabSeedResult, error) {
	raw, err := labSeedSources.ReadFile("labseeds/" + definition.SourceFile)
	if err != nil {
		return LabSeedResult{}, err
	}
	source := string(raw)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])

	var root db.Exp
	err = s.db.WithContext(ctx).Where("tenant_id = ? AND name = ?", tenantID, definition.Name).First(&root).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		root, err = s.CreateExp(ctx, tenantID, actorID, definition.Name, definition.Description, definition.RiskLevel)
	}
	if err != nil {
		return LabSeedResult{}, err
	}
	if root.Status == db.ExpStatusDeprecated {
		return LabSeedResult{}, errors.New("existing lab EXP is deprecated and will not be overwritten")
	}

	var matching db.ExpRevision
	err = s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ? AND source_sha256 = ?", tenantID, root.ID, hash).Order("revision DESC").First(&matching).Error
	if err == nil && matching.Status == db.ExpStatusPublished {
		if root.ActiveRevision == nil || *root.ActiveRevision != matching.Revision {
			if err := s.SetActiveRevision(ctx, tenantID, actorID, root.ID, matching.Revision); err != nil {
				return LabSeedResult{}, err
			}
		}
		return LabSeedResult{Name: definition.Name, ExpID: root.ID, Revision: matching.Revision, SourceSHA256: matching.SourceSHA256, Reused: true}, nil
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return LabSeedResult{}, err
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		matching, err = s.CreateRevision(ctx, tenantID, actorID, root.ID, CreateRevisionInput{Source: source})
		if err != nil {
			return LabSeedResult{}, err
		}
	}

	var seedCase db.ExpTestCase
	testErr := s.db.WithContext(ctx).Where(
		"tenant_id = ? AND exp_id = ? AND revision = ? AND name = ?",
		tenantID, root.ID, matching.Revision, definition.TestCase.Name,
	).First(&seedCase).Error
	switch {
	case errors.Is(testErr, gorm.ErrRecordNotFound):
		if _, err := s.CreateTestCase(ctx, tenantID, actorID, root.ID, matching.Revision, definition.TestCase); err != nil {
			return LabSeedResult{}, err
		}
	case testErr != nil:
		return LabSeedResult{}, testErr
	default:
		if _, err := s.UpdateTestCase(ctx, tenantID, root.ID, seedCase.ID, definition.TestCase); err != nil {
			return LabSeedResult{}, err
		}
	}
	if _, err := s.Inspect(ctx, tenantID, actorID, root.ID, matching.Revision); err != nil {
		return LabSeedResult{}, err
	}
	if _, err := s.Validate(ctx, tenantID, actorID, root.ID, matching.Revision); err != nil {
		return LabSeedResult{}, err
	}
	if _, err := s.Execute(ctx, tenantID, actorID, root.ID, matching.Revision, RunInput{Action: "test", SourceSHA256: matching.SourceSHA256, RiskConfirmed: true, Egress: EgressInput{Mode: "disabled"}}, map[string]any{"mode": "disabled"}); err != nil {
		return LabSeedResult{}, err
	}
	if err := s.Publish(ctx, tenantID, actorID, root.ID, matching.Revision, matching.SourceSHA256); err != nil {
		return LabSeedResult{}, err
	}
	return LabSeedResult{Name: definition.Name, ExpID: root.ID, Revision: matching.Revision, SourceSHA256: matching.SourceSHA256}, nil
}

func developmentLabSeeds() []labSeedDefinition {
	return []labSeedDefinition{
		{
			Name: "lab-shiro-cve-2016-4437-rce", Description: "仅用于 argus-exp-lab 的 Apache Shiro 1.2.4 默认 Key 反序列化 RCE 验收", RiskLevel: "critical", SourceFile: "shiro-cve-2016-4437.yak",
			TestCase: TestCaseInput{Name: "offline-shiro-multistep", Params: mustLabJSON(map[string]any{"target": "http://argus-exp-shiro:8080", "canary_token": "ARGUS_FIXTURE_CANARY_1234", "shiro_key": "kPH+bIxk5D2deZiIxcaaaA=="}), Fixture: json.RawMessage(`{"http":[{"method":"GET","url":"http://argus-exp-shiro:8080","request_headers":{"Cookie":{"exact":"rememberMe=argus-invalid-probe"}},"status_code":302,"response_headers":{"Set-Cookie":"rememberMe=deleteMe"}},{"method":"GET","url":"http://argus-exp-shiro:8080","request_headers":{"Cookie":{"regex":"^rememberMe=.+"}},"status_code":302,"response_headers":{"Location":"/login"}},{"method":"GET","url":"http://argus-exp-shiro:8080","request_headers":{"Cookie":{"regex":"^rememberMe=.+"}},"status_code":302,"response_headers":{"Location":"/login"}},{"method":"GET","url":"http://argus-exp-canary:8080/status/ARGUS_FIXTURE_CANARY_1234","status_code":200,"body":"{\"hit\":true}"}]}`), Expect: json.RawMessage(`{"evidence":{"behavior_detected":true,"crypto_roundtrip":true,"default_key_valid":true,"canary_hit":true,"gadget":"CommonsBeanutils1-1.9.2"}}`)},
		},
		{
			Name: "lab-telnet-unauth-rce", Description: "仅用于 argus-exp-lab 的 Telnet 未认证 Shell 字节交互与命令回显验收", RiskLevel: "critical", SourceFile: "telnet-unauth-rce.yak",
			TestCase: TestCaseInput{Name: "offline-telnet-exchange", Params: json.RawMessage(`{"address":"argus-exp-telnet:23","marker":"ARGUS_FIXTURE_MARKER"}`), Fixture: json.RawMessage(`{"tcp":[{"address":"argus-exp-telnet:23","success":true,"remote_address":"192.0.2.10:23","steps":[{"operation":"read","response":"//0B//0f//sB//sD","encoding":"base64"},{"operation":"write","data":{"exact":"id; echo ARGUS_FIXTURE_MARKER; exit\n"}},{"operation":"read","response":"uid=0(root) gid=0(root) groups=0(root)\r\nARGUS_FIXTURE_MARKER\r\n","encoding":"utf8"}]}]}`), Expect: json.RawMessage(`{"evidence":{"identity_found":true,"marker_found":true}}`)},
		},
	}
}

func mustLabJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

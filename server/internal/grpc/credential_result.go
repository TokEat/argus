package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/TokEat/argus/server/internal/credentialvault"
	"github.com/TokEat/argus/server/internal/db"
	pb "github.com/TokEat/argus/shared/proto/go/scan"
	"gorm.io/gorm/clause"
)

var (
	credentialUsernamePattern = regexp.MustCompile(`(?im)^\s*(?:username|user)\s*:\s*([^\r\n]+)`)
	credentialPasswordPattern = regexp.MustCompile(`(?im)^\s*(?:password|pass)\s*:\s*([^\r\n]*)`)
)

type sealedCredentialFinding struct {
	Username string          `json:"username"`
	Password string          `json:"password"`
	Evidence json.RawMessage `json:"evidence"`
}

func persistCredentialValidationResult(ctx context.Context, result *pb.ScanResult) (bool, error) {
	if result == nil || strings.TrimSpace(result.TaskId) == "" {
		return false, nil
	}
	var attempt db.SubTask
	if err := db.DB.Where("id = ?", result.TaskId).First(&attempt).Error; err != nil || !isCredentialValidationConfig(attempt.Config) {
		return false, nil
	}
	if !agentTransportTLS(ctx) {
		return true, errors.New("credential result requires CA-verified Agent TLS")
	}
	if _, err := validateEmergencyAgentSession(ctx, attempt.AgentID); err != nil {
		return true, err
	}
	if result.PayloadType != "GoPoc" {
		if result.PayloadType == "phase" {
			db.AddResultAsync(result.TaskId, result.PayloadType, string(result.Payload))
			return true, nil
		}
		return true, errors.New("credential validation accepts only phase and GoPoc results")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(result.Payload, &payload); err != nil {
		return true, errors.New("invalid credential result")
	}
	goPoc, _ := payload["go_poc"].(map[string]interface{})
	if goPoc == nil {
		return true, errors.New("credential result is missing go_poc")
	}
	joined := strings.Join([]string{
		mapStringValue(goPoc, "info_left", "InfoLeft"),
		mapStringValue(goPoc, "info_right", "InfoRight"),
		mapStringValue(goPoc, "show_msg", "ShowMsg"),
	}, "\n")
	username, usernamePresent := credentialPatternValue(credentialUsernamePattern, joined)
	password, passwordPresent := credentialPatternValue(credentialPasswordPattern, joined)
	if !usernamePresent && !passwordPresent {
		return true, errors.New("credential result is missing structured credential evidence")
	}
	evidence, err := json.Marshal(goPoc)
	if err != nil {
		return true, err
	}
	secretJSON, err := json.Marshal(sealedCredentialFinding{Username: username, Password: password, Evidence: evidence})
	if err != nil {
		return true, err
	}
	endpoint := mapStringValue(goPoc, "target", "Target")
	findingID := credentialFindingID(attempt.TenantID, attempt.ProjectID, endpoint, username)
	vault, err := credentialvault.NewFromEnvironment(true)
	if err != nil {
		return true, err
	}
	ciphertext, nonce, err := vault.Seal(secretJSON, []byte("finding:"+attempt.TenantID+":"+findingID))
	if err != nil {
		return true, err
	}
	service, plugin, ok := credentialFindingBinding(attempt.Config, endpoint)
	if !ok {
		return true, errors.New("credential result endpoint is not present in the sealed attempt plan")
	}
	finding := db.CredentialFindingSecret{ID: findingID, TenantID: attempt.TenantID, ProjectID: attempt.ProjectID, RootTaskID: attempt.RootTaskID, AttemptID: attempt.ID, Endpoint: endpoint, Service: service, Plugin: plugin, MaskedUsername: maskCredentialUsername(username), Ciphertext: ciphertext, Nonce: nonce}
	if err := db.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"ciphertext", "nonce", "masked_username", "service", "plugin", "attempt_id", "root_task_id"}),
	}).Create(&finding).Error; err != nil {
		return true, err
	}
	// Persist only a masked correlation record through the legacy vulnerability
	// projection. Raw exchange data and successful credentials remain encrypted.
	// Rebuild the projection from an allowlist. Do not mutate the input map:
	// historical Agents used both Go field names and JSON field names, and a
	// forgotten alias could otherwise retain credentials or packet exchanges.
	safePayload := map[string]interface{}{
		"target":   endpoint,
		"service":  service,
		"plugin":   plugin,
		"severity": mapStringValue(goPoc, "security", "Security"),
		"go_poc": map[string]interface{}{
			"poc_name":              plugin,
			"security":              mapStringValue(goPoc, "security", "Security"),
			"target":                endpoint,
			"info_left":             "credential evidence sealed",
			"show_msg":              "credential verified (masked)",
			"credential_finding_id": findingID,
		},
	}
	sanitized, err := json.Marshal(safePayload)
	if err != nil {
		return true, err
	}
	db.AddResultAsync(result.TaskId, result.PayloadType, string(sanitized))
	return true, nil
}

func credentialPatternValue(pattern *regexp.Regexp, value string) (string, bool) {
	matches := pattern.FindStringSubmatch(value)
	if len(matches) == 2 {
		result := strings.TrimSpace(matches[1])
		if strings.EqualFold(result, "<empty>") {
			result = ""
		}
		return result, true
	}
	return "", false
}
func mapStringValue(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if text, ok := values[key].(string); ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	return ""
}

// credentialFindingID 以 租户+项目+端点+用户名(小写) 的 SHA-256 作为 finding 主键，
// 使同一端点的同一账号在多次验证/重扫后收敛到同一行，而不是累积重复行。
// 用户名小写以避免大小写漂移产生重复；展示仍用真实用户名（masked）。
func credentialFindingID(tenantID, projectID, endpoint, username string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		tenantID,
		projectID,
		strings.TrimSpace(endpoint),
		strings.ToLower(strings.TrimSpace(username)),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func credentialFindingBinding(config, endpoint string) (service, plugin string, ok bool) {
	var envelope struct {
		CredentialValidationTargets []struct {
			Endpoint string `json:"endpoint"`
			Service  string `json:"service"`
			Plugin   string `json:"plugin"`
		} `json:"CredentialValidationTargets"`
	}
	if json.Unmarshal([]byte(config), &envelope) != nil {
		return "", "", false
	}
	var matchCount int
	for _, target := range envelope.CredentialValidationTargets {
		// Credential plugins may emit a finding name (for example SSH-Login)
		// different from their dispatcher name (SSH-Crack). The sealed endpoint
		// is unique in a credential plan and remains the authoritative binding.
		if strings.EqualFold(strings.TrimSpace(target.Endpoint), endpoint) {
			service, plugin = strings.TrimSpace(target.Service), strings.TrimSpace(target.Plugin)
			matchCount++
		}
	}
	return service, plugin, matchCount == 1 && plugin != ""
}
func maskCredentialUsername(username string) string {
	username = strings.TrimSpace(username)
	if username == "" {
		return "****"
	}
	if len(username) <= 2 {
		return username[:1] + "*"
	}
	return username[:1] + strings.Repeat("*", len(username)-2) + username[len(username)-1:]
}

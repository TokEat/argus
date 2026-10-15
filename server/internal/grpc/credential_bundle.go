package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/credentialvault"
	"github.com/P0lar1ght/argus/server/internal/db"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func isRiskValidationTask(task *pb.Task) bool {
	if task == nil || len(task.Config) == 0 {
		return false
	}
	var internal struct{ ExecutionMode string }
	return json.Unmarshal(task.Config, &internal) == nil && strings.EqualFold(strings.TrimSpace(internal.ExecutionMode), "risk_validation")
}

func isCredentialValidationTask(task *pb.Task) bool {
	if task == nil || len(task.Config) == 0 {
		return false
	}
	var internal struct{ ExecutionMode string }
	return json.Unmarshal(task.Config, &internal) == nil && strings.EqualFold(strings.TrimSpace(internal.ExecutionMode), "credential_validation")
}

func isCredentialValidationConfig(config string) bool {
	var internal struct{ ExecutionMode string }
	return json.Unmarshal([]byte(config), &internal) == nil && strings.EqualFold(strings.TrimSpace(internal.ExecutionMode), "credential_validation")
}

// isRiskValidationConfig reports whether the attempt carries the derived
// risk-validation stage snapshot. Such failures must be retried through
// credentialbundle.AppendRetry so the immutable stage config (NoPoc=false,
// RiskValidationTargets, pinned rule version) survives into the retry instead
// of being replaced by the Root's asset-discovery revision.
func isRiskValidationConfig(config string) bool {
	var internal struct{ ExecutionMode string }
	return json.Unmarshal([]byte(config), &internal) == nil && strings.EqualFold(strings.TrimSpace(internal.ExecutionMode), "risk_validation")
}

func isSealedNucleiBudgetExceeded(reason string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(reason)), "nuclei request budget exceeded")
}

func agentSupportsCredentialValidation(nodeTagsJSON string) bool {
	return agentHasCapabilities(nodeTagsJSON, "credential_validation", "transport_tls")
}

func (s *Server) FetchCredentialBundle(ctx context.Context, req *pb.FetchCredentialBundleReq) (*pb.FetchCredentialBundleResp, error) {
	if !agentTransportTLS(ctx) {
		return nil, status.Error(codes.FailedPrecondition, "credential bundle requires CA-verified Agent TLS")
	}
	agentID := strings.TrimSpace(req.GetAgentId())
	taskID := strings.TrimSpace(req.GetTaskId())
	ref := strings.TrimSpace(req.GetBundleRef())
	if agentID == "" || taskID == "" || ref == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id, task_id and bundle_ref are required")
	}
	node, err := validateEmergencyAgentSession(ctx, agentID)
	if err != nil {
		return nil, err
	}
	var response *pb.FetchCredentialBundleResp
	err = db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var attempt db.SubTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND tenant_id = ? AND agent_id = ?", taskID, node.TenantID, agentID).First(&attempt).Error; err != nil {
			return err
		}
		if db.CanonicalAttemptState(attempt.Status) != db.AttemptStateRunning {
			return errors.New("attempt is not running")
		}
		var envelope struct {
			CredentialBundleRef    string
			CredentialBundleSHA256 string
			CredentialBundleCount  int
		}
		if json.Unmarshal([]byte(attempt.Config), &envelope) != nil || strings.TrimSpace(envelope.CredentialBundleRef) != ref {
			return errors.New("bundle is not bound to attempt")
		}
		var bundle db.CredentialBundle
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("ref = ? AND tenant_id = ? AND attempt_id = ?", ref, node.TenantID, taskID).First(&bundle).Error; err != nil {
			return err
		}
		now := time.Now().UTC()
		if !bundle.ExpiresAt.After(now) {
			return errors.New("credential bundle expired")
		}
		if bundle.ConsumedAt != nil {
			return errors.New("credential bundle already consumed")
		}
		if bundle.AgentID != "" && bundle.AgentID != agentID {
			return errors.New("credential bundle belongs to another Agent")
		}
		if !strings.EqualFold(strings.TrimSpace(envelope.CredentialBundleSHA256), bundle.SHA256) || envelope.CredentialBundleCount != bundle.PairCount {
			return errors.New("credential bundle does not match attempt contract")
		}
		vault, err := credentialvault.NewFromEnvironment(true)
		if err != nil {
			return err
		}
		plaintext, err := vault.Open(bundle.Ciphertext, bundle.Nonce, []byte("bundle:"+bundle.TenantID+":"+bundle.AttemptID+":"+bundle.Ref))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(plaintext)
		if hex.EncodeToString(sum[:]) != bundle.SHA256 {
			return errors.New("credential bundle hash mismatch")
		}
		var pairs []struct {
			UserName string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(plaintext, &pairs); err != nil {
			return err
		}
		if len(pairs) != bundle.PairCount {
			return errors.New("credential bundle count mismatch")
		}
		bundle.AgentID, bundle.ClaimedAt, bundle.ConsumedAt = agentID, &now, &now
		claim := tx.Model(&db.CredentialBundle{}).Where("ref = ? AND consumed_at IS NULL", bundle.Ref).Updates(map[string]interface{}{"agent_id": agentID, "claimed_at": now, "consumed_at": now})
		if claim.Error != nil {
			return claim.Error
		}
		if claim.RowsAffected != 1 {
			return errors.New("credential bundle already consumed")
		}
		response = &pb.FetchCredentialBundleResp{Sha256: bundle.SHA256, PairCount: int32(bundle.PairCount), ExpiresAtUnix: bundle.ExpiresAt.Unix(), Pairs: make([]*pb.CredentialPair, 0, len(pairs))}
		for _, pair := range pairs {
			response.Pairs = append(response.Pairs, &pb.CredentialPair{Username: pair.UserName, Password: pair.Password})
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "credential bundle or active attempt not found")
		}
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return response, nil
}

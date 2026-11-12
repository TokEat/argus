package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TokEat/argus/scanner/internal/engine"
	"github.com/TokEat/argus/scanner/structs"
	pb "github.com/TokEat/argus/shared/proto/go/scan"
	"google.golang.org/grpc/metadata"
)

func (w *Worker) fetchCredentialBundle(ctx context.Context, taskID, ref string) ([]structs.UserPasswd, error) {
	if !w.transportTLS {
		return nil, errors.New("credential bundle requires CA-verified Agent TLS")
	}
	callCtx := metadata.AppendToOutgoingContext(ctx, "x-agent-token", w.sessionToken)
	resp, err := w.client.FetchCredentialBundle(callCtx, &pb.FetchCredentialBundleReq{AgentId: w.agentID, TaskId: taskID, BundleRef: ref})
	if err != nil {
		return nil, err
	}
	if int(resp.GetPairCount()) != len(resp.GetPairs()) {
		return nil, errors.New("credential bundle count mismatch")
	}
	pairs := make([]structs.UserPasswd, 0, len(resp.GetPairs()))
	for _, pair := range resp.GetPairs() {
		pairs = append(pairs, structs.UserPasswd{UserName: pair.GetUsername(), Password: pair.GetPassword()})
	}
	digest, err := credentialBundleDigest(pairs)
	if err != nil {
		return nil, errors.New("encode credential bundle for integrity check")
	}
	if !strings.EqualFold(digest, strings.TrimSpace(resp.GetSha256())) {
		return nil, errors.New("credential bundle hash mismatch")
	}
	return pairs, nil
}

func (w *Worker) prepareCredentialValidationConfig(cfg *engine.Config, taskID string) error {
	if !strings.EqualFold(strings.TrimSpace(cfg.ExecutionMode), "credential_validation") {
		return nil
	}
	if !w.transportTLS {
		return errors.New("credential validation requires a CA-verified Agent gRPC TLS transport")
	}
	ref := strings.TrimSpace(cfg.CredentialBundleRef)
	if ref == "" {
		return nil
	}
	if w.credentialBundleProvider == nil {
		return errors.New("credential bundle provider is unavailable")
	}
	fetchCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bundle, err := w.credentialBundleProvider(fetchCtx, taskID, ref)
	if err != nil {
		return fmt.Errorf("fetch sealed credential bundle: %w", err)
	}
	if len(bundle) == 0 {
		return errors.New("sealed credential bundle is empty")
	}
	digest, err := credentialBundleDigest(bundle)
	if err != nil {
		return errors.New("encode resolved credential bundle")
	}
	if cfg.CredentialBundleCount != len(bundle) || !strings.EqualFold(strings.TrimSpace(cfg.CredentialBundleSHA256), digest) {
		return errors.New("sealed credential bundle does not match the task contract")
	}
	cfg.CredentialBundle = bundle
	return nil
}

func credentialBundleDigest(pairs []structs.UserPasswd) (string, error) {
	canonical := make([]struct {
		UserName string `json:"username"`
		Password string `json:"password"`
	}, len(pairs))
	for index, pair := range pairs {
		canonical[index].UserName, canonical[index].Password = pair.UserName, pair.Password
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

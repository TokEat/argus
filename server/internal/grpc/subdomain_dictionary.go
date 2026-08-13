package grpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/subdomaindictionary"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"gorm.io/gorm"
)

func (s *Server) resolveClaimSubdomainConfig(tx *gorm.DB, task *pb.Task, sub db.SubTask, resumeConfig []byte, msgID string) ([]byte, bool, error) {
	config := task.Config
	if len(config) == 0 {
		config = []byte(sub.Config)
	}
	if len(resumeConfig) > 0 {
		config = resumeConfig
	}
	config, err := configWithSubdomainDictionary(tx, sub, config)
	if err == nil {
		return config, false, nil
	}
	tx.Rollback()
	if s.returnTaskHook == nil {
		return nil, false, fmt.Errorf("return task %s after subdomain dictionary resolution failed: queue return hook is unavailable: %w", task.TaskId, err)
	}
	if returnErr := s.returnTaskHook(task, msgID); returnErr != nil {
		return nil, false, fmt.Errorf("return task %s after subdomain dictionary resolution failed: %w", task.TaskId, returnErr)
	}
	log.Printf("[ClaimTask] Deferred task %s after subdomain dictionary resolution failed: %v", task.TaskId, err)
	return nil, true, nil
}

func configWithSubdomainDictionary(tx *gorm.DB, sub db.SubTask, config []byte) ([]byte, error) {
	if len(bytes.TrimSpace(config)) == 0 {
		return config, nil
	}
	var metadata struct {
		SubdomainDictionaryRefs []scanpolicy.DictionaryRef
		NoSubdomainBruteForce   bool
	}
	if err := json.Unmarshal(config, &metadata); err != nil {
		return nil, fmt.Errorf("decode subdomain dictionary metadata: %w", err)
	}
	if len(metadata.SubdomainDictionaryRefs) == 0 {
		return config, nil
	}
	if metadata.NoSubdomainBruteForce {
		return nil, fmt.Errorf("subdomain dictionary is bound without bruteforce capability")
	}
	policy := scanpolicy.Policy{Subdomains: scanpolicy.SubdomainPolicy{Wordlists: metadata.SubdomainDictionaryRefs}}
	values, err := subdomaindictionary.LoadValues(tx, policy, sub.TenantID, sub.ProjectID, false)
	if err != nil {
		return nil, err
	}
	return subdomaindictionary.WithValues(config, values)
}

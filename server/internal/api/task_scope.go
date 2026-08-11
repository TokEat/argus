package api

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
)

func decodeStoredTargetList(raw string, allowPlainText bool) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return []string{}, nil
	}

	var targets []string
	if err := json.Unmarshal([]byte(raw), &targets); err == nil {
		return targets, nil
	}
	if allowPlainText {
		return splitTargets(raw), nil
	}
	return nil, fmt.Errorf("stored target scope must be a JSON string array")
}

func mergeStoredTargetList(raw string, additions []string, allowPlainText bool) (encoded string, added []string, total int, err error) {
	existing, err := decodeStoredTargetList(raw, allowPlainText)
	if err != nil {
		return "", nil, 0, err
	}
	existing = normalizeTargetsForMode(existing, taskTargetModeDirect)
	seen := make(map[string]struct{}, len(existing)+len(additions))
	merged := make([]string, 0, len(existing)+len(additions))
	for _, target := range existing {
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		merged = append(merged, target)
	}
	for _, target := range additions {
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		merged = append(merged, target)
		added = append(added, target)
	}
	payload, err := json.Marshal(merged)
	if err != nil {
		return "", nil, 0, err
	}
	return string(payload), added, len(merged), nil
}

func projectDefaultTargets(project db.Project) ([]string, error) {
	seedTargets, err := decodeStoredTargetList(project.SeedTargets, false)
	if err != nil {
		return nil, fmt.Errorf("decode project seed targets: %w", err)
	}
	scopeTargets, err := decodeStoredTargetList(project.Scope, false)
	if err != nil {
		return nil, fmt.Errorf("decode project scope: %w", err)
	}
	return normalizeTargetsForMode(append(seedTargets, scopeTargets...), taskTargetModeDirect), nil
}

func existingTaskTargetSet(batches []db.TaskBatch) (map[string]struct{}, error) {
	seen := make(map[string]struct{})
	for _, batch := range batches {
		targets, err := decodeStoredTargetList(batch.Targets, false)
		if err != nil {
			return nil, fmt.Errorf("decode batch %s targets: %w", batch.ID, err)
		}
		for _, target := range normalizeTargetsForMode(targets, taskTargetModeDirect) {
			seen[target] = struct{}{}
		}
	}
	return seen, nil
}

func filterNewTaskTargets(requested []string, existing map[string]struct{}) (fresh, duplicates []string) {
	for _, target := range requested {
		if _, exists := existing[target]; exists {
			duplicates = append(duplicates, target)
			continue
		}
		existing[target] = struct{}{}
		fresh = append(fresh, target)
	}
	return fresh, duplicates
}

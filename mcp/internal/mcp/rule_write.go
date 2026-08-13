package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (c *Client) argusRuleSave(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ruleType := normalizeRuleType(stringArg(args, "rule_type"))
	fileName := stringArg(args, "file_name")
	content := stringArg(args, "content")
	if ruleType == "" {
		return nil, fmt.Errorf("rule_type is required")
	}
	switch ruleType {
	case "poc", "finger", "workflow":
	default:
		return nil, fmt.Errorf("unsupported rule_type %q", stringArg(args, "rule_type"))
	}
	if fileName == "" {
		switch ruleType {
		case "finger":
			fileName = "finger.yaml"
		case "workflow":
			fileName = "workflow.yaml"
		default:
			return nil, fmt.Errorf("file_name is required for %s save", publicRuleType(ruleType))
		}
	}
	if content == "" {
		var err error
		switch ruleType {
		case "finger":
			content, err = c.composeFingerprintArtifact(ctx, args)
		case "workflow":
			content, err = c.composeWorkflowArtifact(ctx, args)
		default:
			return nil, fmt.Errorf("content is required for %s save", publicRuleType(ruleType))
		}
		if err != nil {
			return nil, err
		}
	}
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/arsenals/"+url.PathEscape(ruleType)+"/"+url.PathEscape(fileName), map[string]interface{}{"content": content}, &out); err != nil {
		return nil, err
	}
	return withStableRef(out, ruleType, fileName), nil
}

func (c *Client) argusRuleApply(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	action := stringArg(args, "action")
	ruleType := normalizeRuleType(stringArg(args, "rule_type"))
	switch action {
	case "publish":
		return c.argusRulePublish(ctx, ruleType, args)
	default:
		return nil, fmt.Errorf("unsupported argus_rule_apply action %q", action)
	}
}

func (c *Client) argusRulePublish(ctx context.Context, ruleType string, args map[string]interface{}) (interface{}, error) {
	if ruleType == "" {
		return nil, fmt.Errorf("rule_type is required")
	}
	fileName := stringArg(args, "file_name")
	if fileName == "" {
		switch ruleType {
		case "finger":
			fileName = "finger.yaml"
		case "workflow":
			fileName = "workflow.yaml"
		default:
			return nil, fmt.Errorf("file_name is required for %s publish", publicRuleType(ruleType))
		}
	}
	if err := c.ensureArtifactFresh(ctx, ruleType, fileName, stringArg(args, "artifact_id"), stringArg(args, "hash"), args["version"]); err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/arsenals/"+url.PathEscape(ruleType)+"/"+url.PathEscape(fileName)+"/approve", nil, &out); err != nil {
		return nil, err
	}
	return withStableRef(out, ruleType, fileName), nil
}

func (c *Client) ensureArtifactFresh(ctx context.Context, ruleType, fileName, artifactID, expectedHash string, expectedVersion interface{}) error {
	if expectedHash == "" && expectedVersion == nil {
		return nil
	}
	var rows []arsenalRecord
	if err := c.do(ctx, http.MethodGet, "/api/v1/arsenals/"+url.PathEscape(ruleType)+"?all=1&lite=1", nil, &rows); err != nil {
		return err
	}
	for _, row := range rows {
		if !arsenalRowMatches(row, ruleType, fileName, artifactID) {
			continue
		}
		currentHash := row.Hash
		if expectedHash != "" && currentHash != expectedHash {
			return fmt.Errorf("artifact hash mismatch for %s: current=%s expected=%s", fileName, currentHash, expectedHash)
		}
		if expectedVersion != nil {
			current := row.VersionInt()
			if row.Version == nil {
				return fmt.Errorf("artifact version is missing for %s", fileName)
			}
			expected, ok := intFromAny(expectedVersion)
			if !ok {
				return fmt.Errorf("expected version is invalid for %s", fileName)
			}
			if current != expected {
				return fmt.Errorf("artifact version mismatch for %s: current=%d expected=%d", fileName, current, expected)
			}
		}
		return nil
	}
	return fmt.Errorf("artifact %s/%s not found", ruleType, fileName)
}

func arsenalRowMatches(row arsenalRecord, ruleType, fileName, artifactID string) bool {
	if artifactID != "" && row.StableID() == artifactID {
		return true
	}
	if row.FileName == fileName {
		return true
	}
	path := strings.TrimPrefix(row.Path, "/")
	return path == ruleType+"/"+fileName
}

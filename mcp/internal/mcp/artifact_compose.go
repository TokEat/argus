package mcp

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

func (c *Client) composeFingerprintArtifact(ctx context.Context, args map[string]interface{}) (string, error) {
	productName := stringArg(args, "product_name")
	rules := stringSliceArg(args, "rules")
	if productName == "" || len(rules) == 0 {
		return "", fmt.Errorf("product_name and rules are required for fingerprint save")
	}
	content, err := c.loadArsenalContent(ctx, "finger", "finger.yaml")
	if err != nil {
		return "", err
	}
	data := map[string][]string{}
	if strings.TrimSpace(content) != "" {
		if err := yaml.Unmarshal([]byte(content), &data); err != nil {
			return "", fmt.Errorf("parse existing finger.yaml: %w", err)
		}
	}
	data[productName] = rules
	out, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type workflowEntry struct {
	Type []string `yaml:"type" json:"type"`
	Pocs []string `yaml:"pocs" json:"pocs"`
}

func (c *Client) composeWorkflowArtifact(ctx context.Context, args map[string]interface{}) (string, error) {
	productName := stringArg(args, "product_name")
	types := stringSliceArg(args, "workflow_types")
	pocs := stringSliceArg(args, "workflow_pocs")
	if productName == "" || len(types) == 0 || len(pocs) == 0 {
		return "", fmt.Errorf("product_name, workflow_types and workflow_pocs are required for workflow save")
	}
	content, err := c.loadArsenalContent(ctx, "workflow", "workflow.yaml")
	if err != nil {
		return "", err
	}
	data := map[string]workflowEntry{}
	if strings.TrimSpace(content) != "" {
		if err := yaml.Unmarshal([]byte(content), &data); err != nil {
			return "", fmt.Errorf("parse existing workflow.yaml: %w", err)
		}
	}
	data[productName] = workflowEntry{Type: types, Pocs: pocs}
	out, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

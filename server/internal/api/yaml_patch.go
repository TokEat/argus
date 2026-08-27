package api

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// upsertYAMLMappingKey replaces or appends one top-level mapping entry and
// leaves every other node (order, comments, scalar style) untouched.
func upsertYAMLMappingKey(existing, key string, value any) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("yaml mapping key is required")
	}
	var valueNode yaml.Node
	if err := valueNode.Encode(value); err != nil {
		return "", fmt.Errorf("encode yaml value: %w", err)
	}

	var doc yaml.Node
	if strings.TrimSpace(existing) == "" {
		doc = yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{{
				Kind: yaml.MappingNode,
				Tag:  "!!map",
			}},
		}
	} else if err := yaml.Unmarshal([]byte(existing), &doc); err != nil {
		return "", fmt.Errorf("parse existing yaml: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return "", fmt.Errorf("expected a YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return "", fmt.Errorf("expected a YAML mapping")
	}

	replaced := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			root.Content[i+1] = &valueNode
			replaced = true
			break
		}
	}
	if !replaced {
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, &valueNode)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

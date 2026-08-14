package api

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

const (
	maxDirPathsPerProduct = 128
	maxDirPathLength      = 2048
)

func normalizeDirPaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one Dir path is required")
	}

	normalized := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for index, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" {
			return nil, fmt.Errorf("Dir path %d must not be empty", index+1)
		}
		if len(path) > maxDirPathLength {
			return nil, fmt.Errorf("Dir path %d exceeds %d bytes", index+1, maxDirPathLength)
		}
		if strings.IndexFunc(path, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("Dir path %d contains control characters", index+1)
		}
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
			return nil, fmt.Errorf("Dir path %d must be a root-relative path beginning with one slash", index+1)
		}
		parsed, err := url.Parse(path)
		if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Opaque != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("Dir path %d must not contain a scheme, host, opaque value, or fragment", index+1)
		}
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		normalized = append(normalized, path)
		if len(normalized) > maxDirPathsPerProduct {
			return nil, fmt.Errorf("Dir paths exceed the per-product limit of %d", maxDirPathsPerProduct)
		}
	}

	return normalized, nil
}

func fingerprintProductReferences(tenantID, product string) ([]string, error) {
	references := make([]string, 0, 2)
	dirs, _, err := fetchAndParseDir(tenantID)
	if err != nil {
		return nil, fmt.Errorf("check dir.yaml references: %w", err)
	}
	if _, exists := dirs[product]; exists {
		references = append(references, "dir.yaml")
	}

	workflows, _, err := fetchAndParseWorkflow(tenantID)
	if err != nil {
		return nil, fmt.Errorf("check workflow.yaml references: %w", err)
	}
	if _, exists := workflows[product]; exists {
		references = append(references, "workflow.yaml")
	}
	sort.Strings(references)
	return references, nil
}

func fingerprintReferenceConflict(product string, references []string) error {
	return fmt.Errorf(
		"product %q is referenced by %s; update those associations before renaming or deleting it",
		product,
		strings.Join(references, " and "),
	)
}

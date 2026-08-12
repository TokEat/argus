// Package resolver validates and indexes the sealed dependency and asset bundle
// supplied by a Yaksha controller. It never reads the host filesystem.
package resolver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/P0lar1ght/argus/yaksha/internal/inspector"
	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
)

type DependencyKey struct {
	ExpID    string
	Revision int
}

type ResolvedDependency struct {
	Definition protocol.Dependency
	Inspection protocol.Inspection
}

type Bundle struct {
	Dependencies map[DependencyKey]ResolvedDependency
	Assets       map[string]string
}

func Validate(req protocol.Request, root protocol.Inspection) (*Bundle, []protocol.Diagnostic) {
	bundle := &Bundle{Dependencies: map[DependencyKey]ResolvedDependency{}, Assets: map[string]string{}}
	diagnostics := []protocol.Diagnostic{}
	for _, item := range req.Dependencies {
		key := DependencyKey{ExpID: item.ExpID, Revision: item.Revision}
		if _, exists := bundle.Dependencies[key]; exists {
			diagnostics = append(diagnostics, diagnostic("duplicate_dependency", fmt.Sprintf("dependency %s revision %d is duplicated", item.ExpID, item.Revision)))
			continue
		}
		childInspection := inspector.Inspect(item.Script)
		if !childInspection.Valid {
			diagnostics = append(diagnostics, diagnostic("invalid_dependency_source", fmt.Sprintf("dependency %s revision %d does not satisfy the EXP contract", item.ExpID, item.Revision)))
		}
		bundle.Dependencies[key] = ResolvedDependency{Definition: item, Inspection: childInspection}
	}
	for _, item := range req.Assets {
		if _, exists := bundle.Assets[item.AssetID]; exists {
			diagnostics = append(diagnostics, diagnostic("duplicate_asset", fmt.Sprintf("asset %s is duplicated", item.AssetID)))
			continue
		}
		content, err := decodeAsset(item)
		if err != nil {
			diagnostics = append(diagnostics, diagnostic("invalid_asset", err.Error()))
			continue
		}
		bundle.Assets[item.AssetID] = content
	}

	reachableDependencies := map[DependencyKey]bool{}
	reachableAssets := map[string]bool{}
	visiting := map[DependencyKey]bool{}
	visited := map[DependencyKey]bool{}
	var visit func(protocol.Inspection)
	visit = func(inspection protocol.Inspection) {
		for _, assetRef := range inspection.AssetRefs {
			reachableAssets[assetRef.AssetID] = true
			if _, ok := bundle.Assets[assetRef.AssetID]; !ok {
				diagnostics = append(diagnostics, at(assetRef.Line, assetRef.Column, "missing_asset", fmt.Sprintf("asset %s is not present in the sealed bundle", assetRef.AssetID)))
			}
		}
		for _, dependencyRef := range inspection.Dependencies {
			key := DependencyKey{ExpID: dependencyRef.ExpID, Revision: dependencyRef.Revision}
			reachableDependencies[key] = true
			dependency, ok := bundle.Dependencies[key]
			if !ok {
				diagnostics = append(diagnostics, at(dependencyRef.Line, dependencyRef.Column, "missing_dependency", fmt.Sprintf("dependency %s revision %d is not present in the sealed bundle", dependencyRef.ExpID, dependencyRef.Revision)))
				continue
			}
			if visiting[key] {
				diagnostics = append(diagnostics, at(dependencyRef.Line, dependencyRef.Column, "dependency_cycle", fmt.Sprintf("dependency cycle reaches %s revision %d", dependencyRef.ExpID, dependencyRef.Revision)))
				continue
			}
			if visited[key] {
				continue
			}
			visiting[key] = true
			visit(dependency.Inspection)
			delete(visiting, key)
			visited[key] = true
		}
	}
	visit(root)

	for key := range bundle.Dependencies {
		if !reachableDependencies[key] {
			diagnostics = append(diagnostics, diagnostic("unused_dependency", fmt.Sprintf("dependency %s revision %d is not referenced", key.ExpID, key.Revision)))
		}
	}
	for assetID := range bundle.Assets {
		if !reachableAssets[assetID] {
			diagnostics = append(diagnostics, diagnostic("unused_asset", fmt.Sprintf("asset %s is not referenced", assetID)))
		}
	}
	return bundle, diagnostics
}

func decodeAsset(item protocol.Asset) (string, error) {
	var raw []byte
	var err error
	if item.Encoding == "base64" {
		raw, err = base64.StdEncoding.Strict().DecodeString(item.Content)
		if err != nil {
			return "", fmt.Errorf("asset %s contains invalid base64: %w", item.AssetID, err)
		}
	} else {
		raw = []byte(item.Content)
	}
	if len(raw) > protocol.MaxResolvedItemBytes {
		return "", fmt.Errorf("asset %s decoded content exceeds %d bytes", item.AssetID, protocol.MaxResolvedItemBytes)
	}
	sum := sha256.Sum256(raw)
	actual := hex.EncodeToString(sum[:])
	if actual != item.SHA256 {
		return "", fmt.Errorf("asset %s sha256 mismatch: expected %s, actual %s", item.AssetID, item.SHA256, actual)
	}
	return string(raw), nil
}

func diagnostic(code, message string) protocol.Diagnostic {
	return at(1, 1, code, message)
}

func at(line, column int, code, message string) protocol.Diagnostic {
	return protocol.Diagnostic{Severity: "error", Code: code, Message: message, Line: line, Column: column}
}

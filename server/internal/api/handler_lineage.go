package api

import (
	"net/http"
	"strings"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/shared/proto/go/targetutil"
	"github.com/gin-gonic/gin"
)

// maxLineageDepth bounds the parent walk so a corrupted source cycle can never
// loop forever (the seen-set is the primary guard; this is the backstop).
const maxLineageDepth = 32

// AssetLineageNode is one step in a scan-lineage chain, root-first. Stage is a
// human-readable producing-stage / label (asset Protocol, vuln plugin, fp
// product, or "input" for the synthetic origin node). For "input" nodes Target
// is the original scan input (the IP/domain the chain started from) and may be
// empty only when no lineage data exists at all.
type AssetLineageNode struct {
	Target   string `json:"target"`
	Stage    string `json:"stage"`
	NodeType string `json:"node_type"` // input | asset | fingerprint | vulnerability
}

// AssetLineageResponse is the root-first lineage chain for a result.
type AssetLineageResponse struct {
	Nodes []AssetLineageNode `json:"nodes"`
}

// buildAssetLineageChain walks startAsset's Source pointers up to the root and
// returns the chain root-first with a synthetic "input" origin node prepended.
// The origin node's Target names the actual scan input the chain started from:
// the root asset's own target when it has no parent reference, or its Source
// reference when the input never materialized as an asset row.
func buildAssetLineageChain(c *gin.Context, projectID string, startAsset db.Asset) []AssetLineageNode {
	tenantID := currentTenantID(c)
	nodes := []AssetLineageNode{}
	seen := map[string]bool{}
	inputTarget := ""
	cur := &startAsset
	for cur != nil && !seen[cur.Target] && len(nodes) < maxLineageDepth {
		seen[cur.Target] = true
		nodes = append([]AssetLineageNode{{Target: cur.Target, Stage: cur.Protocol, NodeType: "asset"}}, nodes...)
		src := strings.TrimSpace(cur.Source)
		if src == "" {
			// No parent reference: the root asset itself is the original input.
			inputTarget = cur.Target
			break
		}
		var parent db.Asset
		err := db.DB.Where("tenant_id = ? AND project_id = ? AND target = ?", tenantID, projectID, src).
			Order("created_at asc").First(&parent).Error
		if err != nil {
			// Input target was never stored as an asset row; Source is its identity.
			inputTarget = src
			break
		}
		cur = &parent
	}
	if inputTarget == "" && cur != nil {
		inputTarget = strings.TrimSpace(cur.Source)
		if inputTarget == "" {
			inputTarget = cur.Target
		}
	}
	return append([]AssetLineageNode{{Target: inputTarget, Stage: "input", NodeType: "input"}}, nodes...)
}

// findHostAsset locates the asset a vuln/fingerprint was detected on by matching
// its (normalized) Target within the project.
func findHostAsset(c *gin.Context, projectID, target string) (db.Asset, bool) {
	tenantID := currentTenantID(c)
	var asset db.Asset
	err := db.DB.Where("tenant_id = ? AND project_id = ? AND target = ?", tenantID, projectID, targetutil.NormalizeTarget(target)).
		Order("created_at asc").First(&asset).Error
	return asset, err == nil
}

func getAssetLineage(c *gin.Context) {
	project, ok := requireProjectAccess(c, strings.TrimSpace(c.Query("project_id")))
	if !ok {
		return
	}
	var asset db.Asset
	if err := db.DB.Where("tenant_id = ? AND project_id = ? AND id = ?", currentTenantID(c), project.ID, c.Param("id")).First(&asset).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
		return
	}
	c.JSON(http.StatusOK, AssetLineageResponse{Nodes: buildAssetLineageChain(c, project.ID, asset)})
}

func getVulnLineage(c *gin.Context) {
	project, ok := requireProjectAccess(c, strings.TrimSpace(c.Query("project_id")))
	if !ok {
		return
	}
	var vuln db.Vulnerability
	if err := db.DB.Where("tenant_id = ? AND project_id = ? AND id = ?", currentTenantID(c), project.ID, c.Param("id")).First(&vuln).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vulnerability not found"})
		return
	}
	nodes := []AssetLineageNode{}
	if host, found := findHostAsset(c, project.ID, vuln.Target); found {
		nodes = buildAssetLineageChain(c, project.ID, host)
	} else {
		nodes = append([]AssetLineageNode{{Target: "", Stage: "input", NodeType: "input"}},
			AssetLineageNode{Target: targetutil.NormalizeTarget(vuln.Target), Stage: "target", NodeType: "asset"})
	}
	nodes = append(nodes, AssetLineageNode{Target: vuln.Target, Stage: vuln.Plugin, NodeType: "vulnerability"})
	c.JSON(http.StatusOK, AssetLineageResponse{Nodes: nodes})
}

func getFingerprintLineage(c *gin.Context) {
	project, ok := requireProjectAccess(c, strings.TrimSpace(c.Query("project_id")))
	if !ok {
		return
	}
	var fp db.FingerprintHit
	if err := db.DB.Where("tenant_id = ? AND project_id = ? AND id = ?", currentTenantID(c), project.ID, c.Param("id")).First(&fp).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "fingerprint not found"})
		return
	}
	nodes := []AssetLineageNode{}
	if host, found := findHostAsset(c, project.ID, fp.Target); found {
		nodes = buildAssetLineageChain(c, project.ID, host)
	} else {
		nodes = append([]AssetLineageNode{{Target: "", Stage: "input", NodeType: "input"}},
			AssetLineageNode{Target: targetutil.NormalizeTarget(fp.Target), Stage: "target", NodeType: "asset"})
	}
	nodes = append(nodes, AssetLineageNode{Target: fp.Target, Stage: fp.ProductName, NodeType: "fingerprint"})
	c.JSON(http.StatusOK, AssetLineageResponse{Nodes: nodes})
}

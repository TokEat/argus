package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (c *Client) expWorkspace(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	action := strings.ToLower(strings.TrimSpace(rawStringArg(args, "action")))
	expID := strings.TrimSpace(rawStringArg(args, "exp_id"))
	revision, hasRevision := workspaceInt(args["revision"])
	assetID := strings.TrimSpace(rawStringArg(args, "asset_id"))
	assetVersion, hasAssetVersion := workspaceInt(args["asset_version"])
	caseID := strings.TrimSpace(rawStringArg(args, "case_id"))
	runID := strings.TrimSpace(rawStringArg(args, "run_id"))

	switch action {
	case "exp_list":
		return c.workspaceGet(ctx, withWorkspacePage("/api/v1/exps", args))
	case "exp_create":
		return c.workspaceJSON(ctx, http.MethodPost, "/api/v1/exps", workspaceFields(args, "name", "description", "risk_level"))
	case "exp_get":
		if expID == "" {
			return nil, fmt.Errorf("exp_id is required")
		}
		return c.workspaceGet(ctx, "/api/v1/exps/"+url.PathEscape(expID))
	case "exp_update":
		if expID == "" {
			return nil, fmt.Errorf("exp_id is required")
		}
		return c.workspaceJSON(ctx, http.MethodPatch, "/api/v1/exps/"+url.PathEscape(expID), workspaceFields(args, "name", "description", "risk_level"))
	case "exp_deprecate":
		if expID == "" {
			return nil, fmt.Errorf("exp_id is required")
		}
		return c.workspaceDelete(ctx, "/api/v1/exps/"+url.PathEscape(expID))
	case "audit_list":
		if expID == "" {
			return nil, fmt.Errorf("exp_id is required")
		}
		return c.workspaceGet(ctx, withWorkspacePage("/api/v1/exps/"+url.PathEscape(expID)+"/audits", args))
	case "risk_waiver_get", "risk_waiver_upsert", "risk_waiver_delete":
		if expID == "" {
			return nil, fmt.Errorf("exp_id is required")
		}
		path := "/api/v1/exps/" + url.PathEscape(expID) + "/risk-waiver"
		switch action {
		case "risk_waiver_get":
			return c.workspaceGet(ctx, path)
		case "risk_waiver_delete":
			return c.workspaceDelete(ctx, path)
		default:
			return c.workspaceJSON(ctx, http.MethodPut, path, workspaceFields(args, "reason", "expires_at"))
		}
	case "revision_list":
		if expID == "" {
			return nil, fmt.Errorf("exp_id is required")
		}
		return c.workspaceGet(ctx, "/api/v1/exps/"+url.PathEscape(expID)+"/revisions")
	case "revision_create":
		if expID == "" {
			return nil, fmt.Errorf("exp_id is required")
		}
		return c.workspaceJSON(ctx, http.MethodPost, "/api/v1/exps/"+url.PathEscape(expID)+"/revisions", workspaceFields(args, "source", "dependencies", "assets"))
	case "revision_get", "revision_inspect", "revision_validate", "revision_publish", "revision_sealed":
		if expID == "" || !hasRevision || revision < 1 {
			return nil, fmt.Errorf("exp_id and positive revision are required")
		}
		base := fmt.Sprintf("/api/v1/exps/%s/revisions/%d", url.PathEscape(expID), revision)
		switch action {
		case "revision_get":
			return c.workspaceGet(ctx, base)
		case "revision_inspect":
			return c.workspaceJSON(ctx, http.MethodPost, base+"/inspect", nil)
		case "revision_validate":
			return c.workspaceJSON(ctx, http.MethodPost, base+"/validate", nil)
		case "revision_publish":
			return c.workspaceJSON(ctx, http.MethodPost, base+"/publish", workspaceFields(args, "source_sha256"))
		default:
			if includeTests, _ := args["include_tests"].(bool); includeTests {
				base += "/sealed-package?include_tests=true"
			} else {
				base += "/sealed-package"
			}
			return c.workspaceGet(ctx, base)
		}
	case "revision_set_active":
		if expID == "" || !hasRevision || revision < 1 {
			return nil, fmt.Errorf("exp_id and positive revision are required")
		}
		return c.workspaceJSON(ctx, http.MethodPost, "/api/v1/exps/"+url.PathEscape(expID)+"/active-revision", map[string]interface{}{"revision": revision})
	case "asset_list":
		return c.workspaceGet(ctx, "/api/v1/exp-assets")
	case "asset_create":
		return c.workspaceJSON(ctx, http.MethodPost, "/api/v1/exp-assets", workspaceFields(args, "asset_id", "media_type", "encoding", "content"))
	case "asset_get":
		if assetID == "" || !hasAssetVersion || assetVersion < 1 {
			return nil, fmt.Errorf("asset_id and positive asset_version are required")
		}
		return c.workspaceGet(ctx, fmt.Sprintf("/api/v1/exp-assets/%s/versions/%d/content", url.PathEscape(assetID), assetVersion))
	case "asset_delete":
		if assetID == "" || !hasAssetVersion || assetVersion < 1 {
			return nil, fmt.Errorf("asset_id and positive asset_version are required")
		}
		return c.workspaceDelete(ctx, fmt.Sprintf("/api/v1/exp-assets/%s/versions/%d", url.PathEscape(assetID), assetVersion))
	case "test_case_list", "test_case_create":
		if expID == "" || !hasRevision || revision < 1 {
			return nil, fmt.Errorf("exp_id and positive revision are required")
		}
		path := fmt.Sprintf("/api/v1/exps/%s/revisions/%d/test-cases", url.PathEscape(expID), revision)
		if action == "test_case_list" {
			return c.workspaceGet(ctx, path)
		}
		return c.workspaceJSON(ctx, http.MethodPost, path, workspaceFields(args, "name", "params", "fixture", "expect", "enabled"))
	case "test_case_update", "test_case_delete":
		if expID == "" || caseID == "" {
			return nil, fmt.Errorf("exp_id and case_id are required")
		}
		path := "/api/v1/exps/" + url.PathEscape(expID) + "/test-cases/" + url.PathEscape(caseID)
		if action == "test_case_delete" {
			return c.workspaceDelete(ctx, path)
		}
		return c.workspaceJSON(ctx, http.MethodPatch, path, workspaceFields(args, "name", "params", "fixture", "expect", "enabled"))
	case "run_list":
		path := withWorkspacePage("/api/v1/exp-runs", args)
		if expID != "" {
			separator := "?"
			if strings.Contains(path, "?") {
				separator = "&"
			}
			path += separator + "exp_id=" + url.QueryEscape(expID)
		}
		return c.workspaceGet(ctx, path)
	case "run_get", "run_cancel":
		if runID == "" {
			return nil, fmt.Errorf("run_id is required")
		}
		path := "/api/v1/exp-runs/" + url.PathEscape(runID)
		if action == "run_cancel" {
			return c.workspaceJSON(ctx, http.MethodPost, path+"/cancel", nil)
		}
		return c.workspaceGet(ctx, path)
	default:
		return nil, fmt.Errorf("unsupported argus_exp_workspace action %q", action)
	}
}

func (c *Client) workspaceGet(ctx context.Context, path string) (interface{}, error) {
	return c.workspaceJSON(ctx, http.MethodGet, path, nil)
}

func (c *Client) workspaceDelete(ctx context.Context, path string) (interface{}, error) {
	if err := c.do(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return nil, err
	}
	return map[string]interface{}{"deleted": true}, nil
}

func (c *Client) workspaceJSON(ctx context.Context, method, path string, body map[string]interface{}) (interface{}, error) {
	var out interface{}
	if err := c.do(ctx, method, path, body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func workspaceFields(args map[string]interface{}, names ...string) map[string]interface{} {
	out := make(map[string]interface{}, len(names))
	for _, name := range names {
		if value, exists := args[name]; exists {
			out[name] = value
		}
	}
	return out
}

func withWorkspacePage(path string, args map[string]interface{}) string {
	query := url.Values{}
	if page, ok := workspaceInt(args["page"]); ok && page > 0 {
		query.Set("page", strconv.Itoa(page))
	}
	if pageSize, ok := workspaceInt(args["page_size"]); ok && pageSize > 0 {
		query.Set("page_size", strconv.Itoa(pageSize))
	}
	if query.Encode() == "" {
		return path
	}
	return path + "?" + query.Encode()
}

func workspaceInt(value interface{}) (int, bool) {
	switch number := value.(type) {
	case int:
		return number, true
	case int64:
		return int(number), int64(int(number)) == number
	case float64:
		return int(number), float64(int(number)) == number
	case json.Number:
		parsed, err := number.Int64()
		return int(parsed), err == nil && int64(int(parsed)) == parsed
	default:
		return 0, false
	}
}

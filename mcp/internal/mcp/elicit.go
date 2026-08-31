package mcp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

const elicitConfirmKey = "confirm"

var errElicitStateMismatch = errors.New("confirmation state does not match this tool call; confirm again")

func maybeElicit(client *Client, tool string, req *sdkmcp.CallToolRequest, args map[string]interface{}) (*sdkmcp.CallToolResult, error) {
	if req == nil || req.Params == nil || !clientSupportsElicitation(req) {
		return nil, nil
	}
	message, needed := elicitMessage(tool, args)
	if len(req.Params.InputResponses) > 0 {
		if err := consumeElicitResponses(client, tool, req, args); err != nil {
			if errors.Is(err, errElicitStateMismatch) && needed {
				return elicitOrError(client, tool, args, message)
			}
			return errorToolResult(err.Error()), nil
		}
		return nil, nil
	}
	if !needed {
		return nil, nil
	}
	return elicitOrError(client, tool, args, message)
}

func clientSupportsElicitation(req *sdkmcp.CallToolRequest) bool {
	caps := req.ClientCapabilities()
	return caps != nil && caps.Elicitation != nil
}

func elicitMessage(tool string, args map[string]interface{}) (string, bool) {
	switch tool {
	case "argus_debug_behavior_probe":
		return "Confirm debugging this behavior probe on the authorized target. Controlled probes may send non-safe HTTP requests and are audited. A risk_confirmed argument is not operator confirmation.", true
	case "argus_scan_create":
		return "Confirm creating this authorized scan with the previewed plan_hash. Review stages, port count, Agent capacity, POC scope and credential budget first.", true
	case "argus_rule_apply":
		if !strings.EqualFold(stringArg(args, "action"), "publish") {
			return "", false
		}
		return "Confirm publishing this Draft with the exact stable_ref hash and version. This changes the active catalog and may sync to Agents.", true
	case "argus_yaksha_exp":
		action := strings.ToLower(stringArg(args, "action"))
		if action != "debug" && action != "run" {
			return "", false
		}
		return "Confirm high-risk EXP debug/run on authorized network targets. Agent egress and execution are audited and cannot bypass tenant authorization. A risk_confirmed argument is not operator confirmation.", true
	default:
		return "", false
	}
}

func elicitOrError(client *Client, tool string, args map[string]interface{}, message string) (*sdkmcp.CallToolResult, error) {
	pending, err := elicitToolResult(client, tool, args, message)
	if err != nil {
		return errorToolResult(err.Error()), nil
	}
	return pending, nil
}

func elicitToolResult(client *Client, tool string, args map[string]interface{}, message string) (*sdkmcp.CallToolResult, error) {
	state, ok := signElicitState(client, tool, args)
	if !ok {
		return nil, fmt.Errorf("operator confirmation requires a Server access token")
	}
	return &sdkmcp.CallToolResult{
		InputRequests: sdkmcp.InputRequestMap{
			elicitConfirmKey: &sdkmcp.ElicitParams{
				Message: message,
				RequestedSchema: &jsonschema.Schema{
					Type: "object",
					Properties: map[string]*jsonschema.Schema{
						"confirmed": {Type: "boolean", Description: "Set true only after the human operator accepts this action"},
					},
					Required: []string{"confirmed"},
				},
			},
		},
		RequestState: state,
	}, nil
}

func consumeElicitResponses(client *Client, tool string, req *sdkmcp.CallToolRequest, args map[string]interface{}) error {
	if !verifyElicitState(client, tool, args, req.Params.RequestState) {
		return errElicitStateMismatch
	}
	raw, ok := req.Params.InputResponses[elicitConfirmKey]
	if !ok || raw == nil {
		return fmt.Errorf("missing confirmation response")
	}
	result, ok := raw.(*sdkmcp.ElicitResult)
	if !ok {
		return fmt.Errorf("invalid confirmation response")
	}
	if result.Action != "accept" {
		return fmt.Errorf("operator declined the confirmation")
	}
	confirmed, _ := result.Content["confirmed"].(bool)
	if !confirmed {
		return fmt.Errorf("operator did not confirm the operation")
	}
	applyElicitConfirmation(tool, args)
	return nil
}

func applyElicitConfirmation(tool string, args map[string]interface{}) {
	switch tool {
	case "argus_debug_behavior_probe", "argus_yaksha_exp":
		args["risk_confirmed"] = true
		if egress, ok := args["egress"].(map[string]interface{}); ok {
			egress["risk_confirmed"] = true
		}
	}
}

func errorToolResult(message string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: message}},
		IsError: true,
	}
}

type elicitState struct {
	Tool  string            `json:"tool"`
	Bound map[string]string `json:"bound"`
}

func elicitBoundFields(tool string, args map[string]interface{}) map[string]string {
	snapshot := cloneArgs(args)
	delete(snapshot, "risk_confirmed")
	if egress, ok := snapshot["egress"].(map[string]interface{}); ok {
		egressCopy := cloneArgs(egress)
		delete(egressCopy, "risk_confirmed")
		snapshot["egress"] = egressCopy
	}
	raw, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(raw)
	return map[string]string{
		"tool":        tool,
		"args_sha256": hex.EncodeToString(sum[:]),
	}
}

func signElicitState(client *Client, tool string, args map[string]interface{}) (string, bool) {
	key, ok := elicitMACKey(client)
	if !ok {
		return "", false
	}
	payload, _ := json.Marshal(elicitState{Tool: tool, Bound: elicitBoundFields(tool, args)})
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), true
}

func verifyElicitState(client *Client, tool string, args map[string]interface{}, state string) bool {
	key, ok := elicitMACKey(client)
	if !ok {
		return false
	}
	payloadPart, macPart, ok := strings.Cut(strings.TrimSpace(state), ".")
	if !ok || payloadPart == "" || macPart == "" {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return false
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(macPart)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(gotMAC, mac.Sum(nil)) {
		return false
	}
	var parsed elicitState
	if json.Unmarshal(payload, &parsed) != nil {
		return false
	}
	if parsed.Tool != tool {
		return false
	}
	want := elicitBoundFields(tool, args)
	if len(parsed.Bound) != len(want) {
		return false
	}
	for key, value := range want {
		if parsed.Bound[key] != value {
			return false
		}
	}
	return true
}

func elicitMACKey(client *Client) ([]byte, bool) {
	if client == nil || client.transport == nil {
		return nil, false
	}
	token := strings.TrimSpace(client.transport.token)
	if token == "" {
		return nil, false
	}
	return []byte(token), true
}

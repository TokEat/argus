package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestMCPProtocolContractSnapshot(t *testing.T) {
	type resourceContract struct {
		URI         string `json:"uri"`
		Name        string `json:"name"`
		Description string `json:"description"`
		MIMEType    string `json:"mime_type"`
		Endpoint    string `json:"endpoint"`
	}
	type toolContract struct {
		Name        string      `json:"name"`
		Description string      `json:"description"`
		InputSchema interface{} `json:"input_schema"`
	}

	resourceSnapshot := make([]resourceContract, 0, len(resources()))
	for _, resource := range resources() {
		resourceSnapshot = append(resourceSnapshot, resourceContract{
			URI: resource.URI, Name: resource.Name, Description: resource.Description,
			MIMEType: resource.MIMEType, Endpoint: resourceEndpoints[resource.URI],
		})
	}
	toolSnapshot := make([]toolContract, 0, len(tools()))
	for _, tool := range tools() {
		toolSnapshot = append(toolSnapshot, toolContract{
			Name: tool.Name, Description: tool.Description, InputSchema: tool.InputSchema,
		})
	}

	data, err := json.Marshal(struct {
		Resources []resourceContract `json:"resources"`
		Tools     []toolContract     `json:"tools"`
	}{Resources: resourceSnapshot, Tools: toolSnapshot})
	if err != nil {
		t.Fatalf("marshal MCP contract: %v", err)
	}
	digest := sha256.Sum256(data)
	got := hex.EncodeToString(digest[:])
	const want = "6965973c98c3ce22ea672951e7cf33f4de63c1aa73aa129c19f7d4f8fd60bd11"
	if got != want {
		t.Fatalf("MCP protocol contract changed: got %s want %s", got, want)
	}
}

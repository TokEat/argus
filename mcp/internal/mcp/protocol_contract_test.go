package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestMCPProtocolContractSnapshot(t *testing.T) {
	type resourceContract struct {
		URI         string      `json:"uri"`
		Name        string      `json:"name"`
		Title       string      `json:"title,omitempty"`
		Description string      `json:"description"`
		MIMEType    string      `json:"mime_type"`
		Endpoint    string      `json:"endpoint"`
		Meta        interface{} `json:"meta,omitempty"`
	}
	type toolContract struct {
		Name         string      `json:"name"`
		Title        string      `json:"title,omitempty"`
		Description  string      `json:"description"`
		InputSchema  interface{} `json:"input_schema"`
		OutputSchema interface{} `json:"output_schema,omitempty"`
		Meta         interface{} `json:"meta,omitempty"`
	}

	resourceSnapshot := make([]resourceContract, 0, len(resources()))
	for _, resource := range resources() {
		resourceSnapshot = append(resourceSnapshot, resourceContract{
			URI: resource.URI, Name: resource.Name, Title: resource.Title, Description: resource.Description,
			MIMEType: resource.MIMEType, Endpoint: resourceEndpoints[resource.URI], Meta: resource.Meta,
		})
	}
	toolSnapshot := make([]toolContract, 0, len(tools()))
	for _, tool := range tools() {
		toolSnapshot = append(toolSnapshot, toolContract{
			Name: tool.Name, Title: tool.Title, Description: tool.Description, InputSchema: tool.InputSchema,
			OutputSchema: tool.OutputSchema, Meta: tool.Meta,
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
	const want = "293a94864fd60ff47e80da18d71279e7ececff2f91ce676c42f681d9d4707f1f"
	if got != want {
		t.Fatalf("MCP protocol contract changed: got %s want %s", got, want)
	}
}

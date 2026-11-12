package mcp

type resourcePayload struct {
	URI      string                 `json:"uri"`
	MIMEType string                 `json:"mime_type"`
	Text     string                 `json:"text"`
	Meta     map[string]interface{} `json:"_meta,omitempty"`
}

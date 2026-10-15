package mcp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
)

const maxDevToolRequest = 4 << 20

type devAppHost struct {
	client *Client
	next   http.Handler
	nonce  string
}

func NewDevAppHost(client *Client, next http.Handler) http.Handler {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		panic("create MCP App development nonce: " + err.Error())
	}
	return &devAppHost{client: client, next: next, nonce: base64.RawURLEncoding.EncodeToString(raw)}
}

func (h *devAppHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/__dev/exp-studio":
		h.serveHost(w, r)
	case "/__dev/exp-studio/app":
		h.serveApp(w, r)
	case "/__dev/tools/call":
		h.callTool(w, r)
	default:
		h.next.ServeHTTP(w, r)
	}
}

func (h *devAppHost) serveHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Yaksha EXP Studio Dev Host</title><style>html,body,iframe{width:100%;height:100%;margin:0;border:0}body{background:#eef2f7}</style></head><body><iframe id="app" src="/__dev/exp-studio/app"></iframe><script>(function(){var frame=document.getElementById('app');var nonce={{.}};window.addEventListener('message',async function(event){if(event.source!==frame.contentWindow||!event.data||event.data.jsonrpc!=='2.0')return;var message=event.data;if(message.method==='ui/initialize'){frame.contentWindow.postMessage({jsonrpc:'2.0',id:message.id,result:{protocolVersion:'2026-01-26',hostInfo:{name:'argus-mcp-dev-host',version:'1'},hostCapabilities:{serverTools:{}}}},'*');return;}if(message.method==='tools/call'){try{var response=await fetch('/__dev/tools/call',{method:'POST',headers:{'Content-Type':'application/json','X-Argus-Dev-Nonce':nonce},body:JSON.stringify(message.params||{})});var value=await response.json();if(!response.ok)throw new Error(value.error||'tool call failed');frame.contentWindow.postMessage({jsonrpc:'2.0',id:message.id,result:value},'*');}catch(error){frame.contentWindow.postMessage({jsonrpc:'2.0',id:message.id,error:{code:-32000,message:error.message}},'*');}return;}if(message.method==='ui/resource-teardown'&&message.id!==undefined)frame.contentWindow.postMessage({jsonrpc:'2.0',id:message.id,result:{}},'*');});}());</script></body></html>`
	_ = template.Must(template.New("host").Parse(page)).Execute(w, h.nonce)
}

func (h *devAppHost) serveApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'self'")
	w.Header().Set("Content-Type", expConsoleMIMEType)
	_, _ = io.WriteString(w, expConsoleHTML)
}

func (h *devAppHost) callTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Argus-Dev-Nonce") != h.nonce {
		http.Error(w, `{"error":"invalid development nonce"}`, http.StatusForbidden)
		return
	}
	var request struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxDevToolRequest)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if request.Name != "argus_yaksha_exp" && request.Name != "argus_exp_workspace" && request.Name != "argus_agents" {
		http.Error(w, `{"error":"tool is not available in EXP Studio"}`, http.StatusForbidden)
		return
	}
	result, err := h.client.CallTool(r.Context(), request.Name, request.Arguments)
	if err != nil {
		writeDevJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	writeDevJSON(w, http.StatusOK, map[string]interface{}{"structuredContent": result})
}

func writeDevJSON(w http.ResponseWriter, status int, value interface{}) {
	raw, err := json.Marshal(value)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

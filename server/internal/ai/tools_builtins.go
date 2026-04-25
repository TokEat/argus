package ai

import (
	"context"
	"encoding/json"
)

// SearchCVEKnowledgeTool removed as per request

// QueryArgusDocsTool 检索 Argus 平台编写规范
type QueryArgusDocsTool struct{}

func (t *QueryArgusDocsTool) Name() string {
	return "QueryArgusDocs"
}

func (t *QueryArgusDocsTool) Description() string {
	return "查询 Argus 平台的 POC 编写规范和 Nuclei YAML 语法最佳实践。"
}

func (t *QueryArgusDocsTool) InputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"query": map[string]interface{}{
				"type":        "string",
				"description": "查询的问题，例如 '如何编写 HTTP matchers'",
			},
		},
		"required": []string{"query"},
	}
}

func (t *QueryArgusDocsTool) Execute(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var args struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return nil, err
	}

	// 返回固定的最佳实践规范
	doc := `
Argus POC 编写规范 (基于 Nuclei)：
1. 必须包含 id 和 info 块 (包含 name, author, severity, tags)。
2. HTTP 协议支持：使用 http 块，支持 method, path, headers, body。
3. Matchers 推荐使用：status, word, regex。可以使用 condition: and/or。
4. 安全规范：严禁使用 rm -rf 等破坏性命令，优先无害验证。
`
	return map[string]interface{}{
		"query": args.Query,
		"doc":   doc,
	}, nil
}

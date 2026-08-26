package arsenal

import (
	"fmt"
	"github.com/P0lar1ght/argus/scanner/lib/ddfinger"
	"github.com/P0lar1ght/argus/scanner/structs"
	"strings"
)

// ValidateFingerRule 校验指纹规则表达式的语法正确性。
// 返回 nil 表示语法正确，否则返回错误信息。
func ValidateFingerRule(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fmt.Errorf("规则表达式不能为空")
	}

	// 检查括号匹配
	if strings.Count(expr, "(") != strings.Count(expr, ")") {
		return fmt.Errorf("左右括号数量不匹配")
	}

	// 检查是否包含至少一条有效规则
	rules := ddfinger.ParseRule(expr)
	if len(rules) == 0 {
		return fmt.Errorf("未解析到有效规则，请确认格式为 key=\"value\" 形式")
	}

	// 验证 key 是否在支持列表中
	validKeys := map[string]bool{
		"body": true, "header": true, "server": true, "title": true,
		"cert": true, "port": true, "protocol": true, "path": true,
		"body_hash": true, "icon_hash": true, "status": true,
		"content_type": true, "banner": true, "type": true,
	}
	for _, rule := range rules {
		if !validKeys[rule.Key] {
			return fmt.Errorf("不支持的匹配字段 \"%s\"，允许的字段: %s",
				rule.Key, strings.Join(validKeysList(), ", "))
		}
	}

	// 尝试 dry-run：用空数据测试，确保不会 panic
	entity := structs.FingerPEntity{
		ProductName: "__test__",
		AllString:   expr,
		Rule:        rules,
	}
	var evalErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				evalErr = fmt.Errorf("规则求值失败: %v", r)
			}
		}()
		_ = ddfinger.SingleCheck(entity, "", "", "", "", "", "", 0, "", "", "", 0, "", "")
	}()
	if evalErr != nil {
		return evalErr
	}

	return nil
}

func validKeysList() []string {
	return []string{
		"body", "header", "server", "title", "cert", "port",
		"protocol", "path", "body_hash", "icon_hash", "status",
		"content_type", "banner", "type",
	}
}

package api

import (
	"reflect"
	"strings"
	"testing"
)

// 修复回归：包内 Poc 唯一性落在 FileName 上，重名模板（不同文件）必须
// 全部下发；任何按 Name 的代表选择都会让另一条工作流引用到不存在的文件。
func TestAgentPocSchemaKeysUniquenessOnFileName(t *testing.T) {
	nameField, ok := reflect.TypeOf(agentPoc{}).FieldByName("Name")
	if !ok {
		t.Fatal("agentPoc.Name field missing")
	}
	if strings.Contains(nameField.Tag.Get("gorm"), "uniqueIndex") {
		t.Fatalf("agentPoc.Name must not carry uniqueIndex (duplicate template names are legitimate), tag=%q", nameField.Tag.Get("gorm"))
	}
	fileField, ok := reflect.TypeOf(agentPoc{}).FieldByName("FileName")
	if !ok {
		t.Fatal("agentPoc.FileName field missing")
	}
	if !strings.Contains(fileField.Tag.Get("gorm"), "uniqueIndex") {
		t.Fatalf("agentPoc.FileName must be uniqueIndex, tag=%q", fileField.Tag.Get("gorm"))
	}
}

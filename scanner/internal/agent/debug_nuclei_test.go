package agent

import (
	"errors"
	"testing"
)

func TestCompleteNucleiDebugReportsExecutionFailure(t *testing.T) {
	var message string
	completeNucleiDebug(func(value string) { message = value }, errors.New("runner failed"))
	if message != "runner failed" {
		t.Fatalf("completion message = %q", message)
	}
}

func TestIsNucleiDeprecatedCatalogLog(t *testing.T) {
	if !isNucleiDeprecatedCatalogLog("[WRN] 发现 12 个模板加载了不推荐使用的协议语法") {
		t.Fatal("expected Chinese deprecated-protocol banner to be filtered")
	}
	if !isNucleiDeprecatedCatalogLog("Found 12 template[s] loaded with deprecated paths") {
		t.Fatal("expected deprecated path banner to be filtered")
	}
	if isNucleiDeprecatedCatalogLog("running nuclei debug against http://target") {
		t.Fatal("ordinary debug log must not be filtered")
	}
}

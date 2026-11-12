// Package output projects Nuclei results onto the canonical scanner output
// stream consumed by result.txt, CLI observers, and Agent hooks.
package output

import (
	"encoding/json"
	"fmt"

	"github.com/TokEat/argus/scanner/ddout"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// AddResultByResultEvent projects a Nuclei event onto the canonical scanner
// output stream. CLI reports and result.txt consume the same structured event;
// Agent callers continue to use their existing output hook.
func AddResultByResultEvent(result nucleiOutput.ResultEvent) {
	payload, err := json.Marshal(result)
	if err != nil {
		return
	}
	show := fmt.Sprintf("[%s] [%s] %v", result.TemplateID,
		result.Info.SeverityHolder.Severity.String(), result.Matched)
	ddout.FormatOutput(ddout.OutputMessage{
		Type:   "Nuclei",
		Nuclei: string(payload),
		Show:   show,
	})
}

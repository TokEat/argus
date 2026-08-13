package gopocs

import (
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

func TestDispatchGoPocTargetsUsesOnlySealedProtocolPlan(t *testing.T) {
	original := PluginList["DNP3-Scan"]
	t.Cleanup(func() { PluginList["DNP3-Scan"] = original })
	called := 0
	PluginList["DNP3-Scan"] = func(info *structs.HostInfo) error {
		called++
		result := structs.GoPocsResultType{PocName: "DNP3-Scan", Target: info.Host + ":" + info.Ports}
		info.WriteResult(result)
		info.Emit(structs.OutputMessage{Type: "GoPoc", GoPoc: result})
		return nil
	}
	targets := scanpolicy.GoPocTargetsForEndpoint("192.0.2.10:20000", "dnp3", 20000, strings.Repeat("a", 64), scanpolicy.GoPocProtocolCheck)
	var emitted []structs.OutputMessage
	results, err := DispatchGoPocTargets(targets, scanpolicy.GoPocCatalogSHA256(), scanpolicy.GoPocProtocolCheck, 1, 1000, 1, func(message structs.OutputMessage) {
		emitted = append(emitted, message)
	})
	if err != nil {
		t.Fatal(err)
	}
	if called != 1 || len(results) != 1 || len(emitted) != 1 || emitted[0].Type != "ProtocolCheck" || emitted[0].Protocol != "dnp3" {
		t.Fatalf("unexpected scoped dispatch: called=%d results=%+v emitted=%+v", called, results, emitted)
	}
}

func TestDispatchGoPocTargetsFailsClosedOnCatalogOrBudgetDrift(t *testing.T) {
	targets := scanpolicy.GoPocTargetsForEndpoint("192.0.2.10:20000", "dnp3", 20000, strings.Repeat("a", 64), scanpolicy.GoPocProtocolCheck)
	if _, err := DispatchGoPocTargets(targets, strings.Repeat("0", 64), scanpolicy.GoPocProtocolCheck, 1, 1, 1, nil); err == nil {
		t.Fatal("catalog drift was accepted")
	}
	if _, err := DispatchGoPocTargets(targets, scanpolicy.GoPocCatalogSHA256(), scanpolicy.GoPocProtocolCheck, 1, 1, 0, nil); err == nil {
		t.Fatal("zero request budget was accepted")
	}
}

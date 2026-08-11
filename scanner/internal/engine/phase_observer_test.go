package engine

import "testing"

func TestEmitPhaseNotifiesObserverAndHook(t *testing.T) {
	var observed, hooked PhaseEvent
	ctx := &ScanContext{
		LocalForceFullScan: true,
		PhaseObserver:      func(event PhaseEvent) { observed = event },
		PhaseHook:          func(event PhaseEvent) { hooked = event },
	}
	emitPhase(ctx, PhasePortScan, "end", "complete")
	if observed.Phase != PhasePortScan || hooked != observed {
		t.Fatalf("observer=%#v hook=%#v", observed, hooked)
	}
	ctx.Reset()
	if ctx.PhaseObserver != nil {
		t.Fatal("Reset did not clear PhaseObserver")
	}
	if !ctx.LocalForceFullScan {
		t.Fatal("Reset cleared the CLI force policy between target executions")
	}
}

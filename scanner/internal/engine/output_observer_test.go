package engine

import (
	"reflect"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func TestDispatchPipelineOutputMirrorsBeforeAgentHook(t *testing.T) {
	want := structs.OutputMessage{Type: "Web", IP: "192.0.2.10", Port: "443", URI: "https://example.test"}
	order := []string{}
	var observed, hooked OutputMessage
	ctx := &ScanContext{
		OutputObserver: func(message OutputMessage) {
			order = append(order, "observer")
			observed = message
		},
		OutputHook: func(message OutputMessage) {
			order = append(order, "hook")
			hooked = message
		},
	}
	dispatchPipelineOutput(ctx, want)
	converted := toEngineOutputMessage(want)
	if !reflect.DeepEqual(observed, converted) || !reflect.DeepEqual(hooked, converted) {
		t.Fatalf("observer = %#v, hook = %#v, want %#v", observed, hooked, converted)
	}
	if !reflect.DeepEqual(order, []string{"observer", "hook"}) {
		t.Fatalf("dispatch order = %v", order)
	}
}

func TestNucleiResultMirrorsToObserverAndAgentHook(t *testing.T) {
	var observed, hooked OutputMessage
	ctx := &ScanContext{
		OutputObserver: func(message OutputMessage) { observed = message },
		OutputHook:     func(message OutputMessage) { hooked = message },
	}
	handler, collector := buildNucleiResultHandler(ctx, false)
	handler(nucleiOutput.ResultEvent{TemplateID: "safe-check", Matched: "https://example.test"})
	if observed.Type != "Nuclei" || observed.Nuclei == "" || !reflect.DeepEqual(observed, hooked) {
		t.Fatalf("observer = %#v, hook = %#v", observed, hooked)
	}
	if results := collector.snapshot(); len(results) != 1 || results[0].TemplateID != "safe-check" {
		t.Fatalf("collector results = %#v", results)
	}
}

func TestAuthoritativeNucleiResultsDoesNotDuplicateCallbackEvents(t *testing.T) {
	event := nucleiOutput.ResultEvent{TemplateID: "safe-check", Matched: "https://example.test"}
	results := authoritativeNucleiResults([]nucleiOutput.ResultEvent{event}, []nucleiOutput.ResultEvent{event})
	if len(results) != 1 || results[0].TemplateID != event.TemplateID {
		t.Fatalf("authoritative results = %#v", results)
	}
}

func TestResetClearsCLIObserver(t *testing.T) {
	ctx := &ScanContext{LocalRunID: "run-1", OutputObserver: func(OutputMessage) {}}
	ctx.Reset()
	if ctx.LocalRunID != "" || ctx.OutputObserver != nil {
		t.Fatalf("Reset retained CLI-only state: run=%q observer=%v", ctx.LocalRunID, ctx.OutputObserver != nil)
	}
}

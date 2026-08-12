package testrunner_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/yaksha/internal/egress"
	"github.com/P0lar1ght/argus/yaksha/internal/engine"
	"github.com/P0lar1ght/argus/yaksha/internal/inspector"
	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
	"github.com/P0lar1ght/argus/yaksha/internal/testrunner"
	"github.com/P0lar1ght/argus/yaksha/internal/validator"
)

func TestRealEXPFileVerticalRuntimeLoop(t *testing.T) {
	sourcePath := filepath.Join("..", "..", "testdata", "http-marker-check.yak")
	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)

	inspection := inspector.Inspect(source)
	if !inspection.Valid || len(inspection.Parameters) != 2 {
		t.Fatalf("inspection=%#v", inspection)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("yaksha-marker"))
	}))
	defer server.Close()
	target := server.URL + "/probe?debug=full-detail"
	params := map[string]any{"target": target}

	validation := validator.Validate(protocol.Request{Action: protocol.ActionValidate, Script: source, Params: params})
	if !validation.Validation.Valid {
		t.Fatalf("validation=%#v", validation.Validation)
	}

	run := engine.ExecuteWithEgress(protocol.Request{Action: protocol.ActionRun, Script: source, Params: params, NetworkTargets: []string{server.URL}}, egress.NewDirectClient(nil, true))
	if run.Status != protocol.StatusSucceeded || run.Evidence["marker_matched"] != true {
		t.Fatalf("run=%#v", run)
	}

	debug := engine.ExecuteWithEgress(protocol.Request{Action: protocol.ActionDebug, Script: source, Params: params, NetworkTargets: []string{server.URL}}, egress.NewDirectClient(nil, true))
	if debug.Status != protocol.StatusSucceeded || debug.Debug == nil || len(debug.Debug.Events) != 1 || debug.Debug.Events[0].Target != target {
		t.Fatalf("debug=%#v", debug)
	}
	if !strings.Contains(debug.Debug.Events[0].Target, "debug=full-detail") {
		t.Fatalf("debug target lost detail: %#v", debug.Debug.Events[0])
	}

	expectedResult := json.RawMessage(`{"vulnerable":true,"response":"200 yaksha-marker"}`)
	report := testrunner.Run(protocol.Request{
		Action: protocol.ActionTest,
		Script: source,
		TestCases: []protocol.TestCase{{
			ID:     "fixture-marker",
			Params: map[string]any{"target": "http://fixture.invalid/probe"},
			Fixture: &protocol.Fixture{HTTP: []protocol.HTTPFixture{{
				Method: http.MethodGet, URL: "http://fixture.invalid/probe", StatusCode: 200, Body: "yaksha-marker",
			}}},
			Expect: protocol.TestExpectation{
				Result:   expectedResult,
				Evidence: map[string]json.RawMessage{"marker_matched": json.RawMessage(`true`)},
			},
		}},
	})
	if report.Passed != 1 || report.Failed != 0 {
		t.Fatalf("test report=%#v", report)
	}
}

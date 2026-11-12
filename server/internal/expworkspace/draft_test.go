package expworkspace

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
)

func TestDraftFixtureAcceptanceBindsExactPackageBeforeRevisionSave(t *testing.T) {
	var validateCalls atomic.Int32
	var testCalls atomic.Int32
	runtimeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request RuntimeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.ExpID != "" || request.Revision != 0 || request.SourceSHA256 != "" {
			t.Fatalf("in-memory draft must not impersonate a persisted Revision: %+v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Action {
		case "inspect":
			_, _ = w.Write([]byte(`{"status":"Succeeded","inspection":{"valid":true,"parameters":[{"name":"target","type":"string","input_type":"url"}],"control_flow":[{"id":"step-1","kind":"request","operation":"yaksha.httpRequest","label":"HTTP 请求"}]}}`))
		case "validate":
			validateCalls.Add(1)
			if request.ValidationMode != "contract" {
				t.Fatalf("validation mode=%q", request.ValidationMode)
			}
			_, _ = w.Write([]byte(`{"status":"Succeeded","inspection":{"valid":true,"parameters":[{"name":"target","type":"string","input_type":"url"}]},"validation":{"valid":true}}`))
		case "test":
			testCalls.Add(1)
			if stringValue(request.Egress, "mode") != "disabled" || len(request.NetworkTargets) != 0 || len(request.TestCases) != 1 {
				t.Fatalf("draft Fixture test must stay sealed and offline: %+v", request)
			}
			_, _ = w.Write([]byte(`{"status":"Succeeded","test":{"passed":1,"failed":0}}`))
		default:
			t.Fatalf("unexpected Runtime action %q", request.Action)
		}
	}))
	defer runtimeServer.Close()

	service, database := newTestService(t)
	runtime, err := NewRuntimeClient(runtimeServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	service.runtime = runtime
	ctx := context.Background()
	exp, err := service.CreateExp(ctx, "tenant-a", "operator-a", "live-draft", "", "high")
	if err != nil {
		t.Fatal(err)
	}
	source := `target = cli.String("target", cli.setInputType("url")); cli.check(); yaksha.result(target)`
	input := DraftPackageInput{
		Source: source,
		TestCases: []TestCaseInput{{
			Name: "offline", Params: json.RawMessage(`{"target":"http://fixture.invalid:80"}`),
			Fixture: json.RawMessage(`{}`), Expect: json.RawMessage(`{"result":"http://fixture.invalid:80"}`),
		}},
	}

	inspection, err := service.InspectDraft(ctx, "tenant-a", exp.ID, source)
	if err != nil || !strings.Contains(toTestJSON(inspection), "control_flow") {
		t.Fatalf("live inspection=%s err=%v", toTestJSON(inspection), err)
	}
	if _, err := service.InspectDraft(ctx, "tenant-b", exp.ID, source); err == nil {
		t.Fatal("cross-tenant live inspection must not resolve another tenant EXP")
	}

	accepted, err := service.TestDraft(ctx, "tenant-a", "operator-a", exp.ID, input)
	if err != nil || accepted.TestReceipt == "" || accepted.ExpiresAt.IsZero() {
		t.Fatalf("draft acceptance=%+v err=%v", accepted, err)
	}
	if validateCalls.Load() != 1 || testCalls.Load() != 1 {
		t.Fatalf("contract/test calls=%d/%d", validateCalls.Load(), testCalls.Load())
	}

	changed := input
	changed.Source += "; yaksha.log(" + `"changed"` + ")"
	if _, err := service.CreateTestedRevision(ctx, "tenant-a", "operator-a", exp.ID, CreateTestedRevisionInput{DraftPackageInput: changed, TestReceipt: accepted.TestReceipt}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("changed package must invalidate receipt, got %v", err)
	}
	if _, err := service.CreateTestedRevision(ctx, "tenant-a", "operator-b", exp.ID, CreateTestedRevisionInput{DraftPackageInput: input, TestReceipt: accepted.TestReceipt}); err == nil {
		t.Fatal("another operator must not consume the receipt")
	}

	revision, err := service.CreateTestedRevision(ctx, "tenant-a", "operator-a", exp.ID, CreateTestedRevisionInput{DraftPackageInput: input, TestReceipt: accepted.TestReceipt})
	if err != nil {
		t.Fatal(err)
	}
	if revision.Revision != 1 || revision.TestsPassedAt == nil || revision.TestCasesSHA256 == "" || !strings.Contains(revision.CLISchema, "target") {
		t.Fatalf("unexpected accepted revision: %+v", revision)
	}
	var caseCount int64
	if err := database.Model(&db.ExpTestCase{}).Where("tenant_id = ? AND exp_id = ? AND revision = ?", "tenant-a", exp.ID, revision.Revision).Count(&caseCount).Error; err != nil {
		t.Fatal(err)
	}
	if caseCount != 1 {
		t.Fatalf("saved Fixture count=%d", caseCount)
	}
	if _, err := service.CreateTestedRevision(ctx, "tenant-a", "operator-a", exp.ID, CreateTestedRevisionInput{DraftPackageInput: input, TestReceipt: accepted.TestReceipt}); err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("receipt replay must fail, got %v", err)
	}
}

func TestDraftFixtureAcceptanceRequiresContractAndEnabledFixture(t *testing.T) {
	var testCalls atomic.Int32
	runtimeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request RuntimeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		if request.Action == "validate" {
			_, _ = w.Write([]byte(`{"status":"Succeeded","inspection":{"valid":true},"validation":{"valid":false,"diagnostics":[{"severity":"error","message":"invalid"}]}}`))
			return
		}
		testCalls.Add(1)
		_, _ = w.Write([]byte(`{"status":"Succeeded","test":{"failed":0}}`))
	}))
	defer runtimeServer.Close()

	service, _ := newTestService(t)
	runtime, err := NewRuntimeClient(runtimeServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	service.runtime = runtime
	exp, err := service.CreateExp(context.Background(), "tenant-a", "operator", "invalid-contract", "", "high")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.TestDraft(context.Background(), "tenant-a", "operator", exp.ID, DraftPackageInput{Source: "cli.check()"}); err == nil || !strings.Contains(err.Error(), "enabled Fixture") {
		t.Fatalf("missing Fixture must fail before Runtime, got %v", err)
	}
	input := DraftPackageInput{Source: "cli.check()", TestCases: []TestCaseInput{{Name: "offline", Params: json.RawMessage(`{}`), Fixture: json.RawMessage(`{}`), Expect: json.RawMessage(`{}`)}}}
	result, err := service.TestDraft(context.Background(), "tenant-a", "operator", exp.ID, input)
	if err == nil || !strings.Contains(err.Error(), "contract validation") || result.TestReceipt != "" || testCalls.Load() != 0 {
		t.Fatalf("invalid contract must not execute Fixture: result=%+v err=%v calls=%d", result, err, testCalls.Load())
	}
}

func toTestJSON(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

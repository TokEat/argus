package testrunner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/TokEat/argus/yaksha/internal/protocol"
)

func TestRunEvaluatesStructuredAssertions(t *testing.T) {
	script := `
input = cli.Int("input", cli.setRequired(true))
cli.check()
value = input * 2
yaksha.log("input=" + yaksha.toString(input))
yaksha.evidence("double", value)
yaksha.result(value)
`
	report := Run(protocol.Request{
		ID:     "test-1",
		Action: protocol.ActionTest,
		Script: script,
		TestCases: []protocol.TestCase{
			{
				ID:     "passes",
				Params: map[string]any{"input": 2},
				Expect: protocol.TestExpectation{
					Result:      json.RawMessage(`4`),
					Evidence:    map[string]json.RawMessage{"double": json.RawMessage(`4`)},
					LogsContain: []string{"input=2"},
				},
			},
			{
				ID:     "fails assertion",
				Params: map[string]any{"input": 3},
				Expect: protocol.TestExpectation{Result: json.RawMessage(`7`)},
			},
		},
	})
	if report.Passed != 1 || report.Failed != 1 || len(report.Cases) != 2 {
		t.Fatalf("report=%#v", report)
	}
	if !report.Cases[0].Passed || report.Cases[1].Passed || len(report.Cases[1].AssertionFailures) != 1 {
		t.Fatalf("cases=%#v", report.Cases)
	}
}

func TestRunUsesFailClosedHTTPFixture(t *testing.T) {
	target := "http://fixture.invalid/probe?case=full"
	script := `
target = cli.String("target", cli.setRequired(true))
cli.check()
value, err = yaksha.httpGet(target)
if err != nil { panic(err) }
yaksha.result(value)
`
	t.Run("matched", func(t *testing.T) {
		report := Run(protocol.Request{Script: script, TestCases: []protocol.TestCase{{
			ID:     "matched",
			Params: map[string]any{"target": target},
			Fixture: &protocol.Fixture{HTTP: []protocol.HTTPFixture{{
				Method: "GET", URL: target, StatusCode: 201, Body: "fixture-body",
			}}},
			Expect: protocol.TestExpectation{Result: json.RawMessage(`"201 fixture-body"`)},
		}}})
		if report.Failed != 0 || len(report.Cases[0].Events) != 1 || report.Cases[0].Events[0].Target != target {
			t.Fatalf("report=%#v", report)
		}
	})

	t.Run("unmatched never uses real network", func(t *testing.T) {
		report := Run(protocol.Request{Script: script, TestCases: []protocol.TestCase{{
			ID:      "unmatched",
			Params:  map[string]any{"target": target},
			Fixture: &protocol.Fixture{},
			Expect: protocol.TestExpectation{
				Status:        protocol.StatusFailed,
				ErrorContains: "no matching HTTP fixture",
			},
		}}})
		if report.Failed != 0 || !report.Cases[0].Passed || !strings.Contains(report.Cases[0].Error, "no matching HTTP fixture") {
			t.Fatalf("report=%#v", report)
		}
	})
}

func TestRunUsesTCPFixture(t *testing.T) {
	address := "fixture.invalid:443"
	script := `address = cli.String("address", cli.setRequired(true)); cli.check(); value, err = yaksha.dial(address); if err != nil { panic(err) }; yaksha.result(value)`
	report := Run(protocol.Request{Script: script, TestCases: []protocol.TestCase{{
		ID:     "tcp",
		Params: map[string]any{"address": address},
		Fixture: &protocol.Fixture{TCP: []protocol.TCPFixture{{
			Address: address, Success: true, RemoteAddress: "fixture-remote:443",
		}}},
		Expect: protocol.TestExpectation{Result: json.RawMessage(`"fixture-remote:443"`)},
	}}})
	if report.Failed != 0 || !report.Cases[0].Passed || len(report.Cases[0].Events) != 1 {
		t.Fatalf("report=%#v", report)
	}
}

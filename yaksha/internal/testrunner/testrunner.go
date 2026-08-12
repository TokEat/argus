// Package testrunner executes repeatable EXP cases with fail-closed fixtures
// and evaluates structured assertions.
package testrunner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/yaksha/internal/engine"
	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
)

func Run(req protocol.Request) protocol.TestReport {
	report := protocol.TestReport{Cases: make([]protocol.TestCaseResult, 0, len(req.TestCases))}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Duration(protocol.DefaultTimeoutMS) * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	for _, testCase := range req.TestCases {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			result := protocol.TestCaseResult{
				ID:                testCase.ID,
				Status:            protocol.StatusTimeout,
				Error:             "test request timeout exhausted before case execution",
				AssertionFailures: []string{"case was not executed: test request timeout exhausted"},
			}
			report.Failed++
			report.Cases = append(report.Cases, result)
			continue
		}
		caseTimeoutMS := remaining.Milliseconds()
		if caseTimeoutMS < 1 {
			caseTimeoutMS = 1
		}
		response := engine.ExecuteTestCase(protocol.Request{
			ID:             testCase.ID,
			Action:         protocol.ActionRun,
			Script:         req.Script,
			Params:         testCase.Params,
			TimeoutMS:      caseTimeoutMS,
			Dependencies:   req.Dependencies,
			Assets:         req.Assets,
			NetworkTargets: nil,
		}, testCase.Fixture)

		result := protocol.TestCaseResult{
			ID:                testCase.ID,
			Status:            response.Status,
			Result:            response.Result,
			Evidence:          response.Evidence,
			Logs:              response.Logs,
			Error:             response.Error,
			Calls:             response.Calls,
			AssertionFailures: []string{},
		}
		if response.Debug != nil {
			result.Events = response.Debug.Events
		}
		assertCase(&result, testCase.Expect)
		result.Passed = len(result.AssertionFailures) == 0
		if result.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
		report.Cases = append(report.Cases, result)
	}
	return report
}

func assertCase(result *protocol.TestCaseResult, expect protocol.TestExpectation) {
	wantStatus := expect.Status
	if wantStatus == "" {
		wantStatus = protocol.StatusSucceeded
	}
	if result.Status != wantStatus {
		result.AssertionFailures = append(result.AssertionFailures, fmt.Sprintf("status: got %s, want %s", result.Status, wantStatus))
	}
	if len(expect.Result) > 0 && !jsonEqual(result.Result, expect.Result) {
		result.AssertionFailures = append(result.AssertionFailures, "result does not equal expected JSON")
	}
	evidenceKeys := make([]string, 0, len(expect.Evidence))
	for key := range expect.Evidence {
		evidenceKeys = append(evidenceKeys, key)
	}
	sort.Strings(evidenceKeys)
	for _, key := range evidenceKeys {
		expected := expect.Evidence[key]
		actual, exists := result.Evidence[key]
		if !exists {
			result.AssertionFailures = append(result.AssertionFailures, fmt.Sprintf("evidence %q is missing", key))
			continue
		}
		if !jsonEqual(actual, expected) {
			result.AssertionFailures = append(result.AssertionFailures, fmt.Sprintf("evidence %q does not equal expected JSON", key))
		}
	}
	for _, fragment := range expect.LogsContain {
		found := false
		for _, logLine := range result.Logs {
			if strings.Contains(logLine, fragment) {
				found = true
				break
			}
		}
		if !found {
			result.AssertionFailures = append(result.AssertionFailures, fmt.Sprintf("logs do not contain %q", fragment))
		}
	}
	if expect.ErrorContains != "" && !strings.Contains(result.Error, expect.ErrorContains) {
		result.AssertionFailures = append(result.AssertionFailures, fmt.Sprintf("error does not contain %q", expect.ErrorContains))
	}
}

func jsonEqual(actual any, expected json.RawMessage) bool {
	actualRaw, err := json.Marshal(actual)
	if err != nil {
		return false
	}
	var actualValue any
	var expectedValue any
	decoder := json.NewDecoder(bytes.NewReader(actualRaw))
	decoder.UseNumber()
	if err := decoder.Decode(&actualValue); err != nil {
		return false
	}
	decoder = json.NewDecoder(bytes.NewReader(expected))
	decoder.UseNumber()
	if err := decoder.Decode(&expectedValue); err != nil {
		return false
	}
	actualNormalized, _ := json.Marshal(actualValue)
	expectedNormalized, _ := json.Marshal(expectedValue)
	return bytes.Equal(actualNormalized, expectedNormalized)
}

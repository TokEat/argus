package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

func TestMakeResultEventItemPreservesPacketBeyondTwentyOneSteps(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	templateID := "packet-more-than-twenty-one-steps"
	request := &Request{
		ID:     templateID,
		Name:   "packet regression",
		Path:   []string{"{{BaseURL}}/packet"},
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
	}
	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: templateID,
		Info: model.Info{
			Name:           "Packet regression",
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
	})
	require.NoError(t, request.Compile(executerOptions))

	internal := output.InternalEvent{
		"host":          "https://scan.example.test/packet",
		"matched":       "https://scan.example.test/packet",
		"template-id":   templateID,
		"template-path": "packet-regression.yaml",
		"template-info": executerOptions.TemplateInfo,
		"type":          "http",
		"request":       "main-request",
		"response":      "main-response",
	}
	const stepCount = 25
	for index := 0; index < stepCount; index++ {
		internal[fmt.Sprintf("request_%d", index)] = fmt.Sprintf("request-step-%d", index)
		internal[fmt.Sprintf("response_%d", index)] = fmt.Sprintf("response-step-%d", index)
	}

	result := request.MakeResultEventItem(&output.InternalWrappedEvent{
		InternalEvent: internal,
		OperatorsResult: &operators.Result{
			PayloadValues: map[string]interface{}{},
		},
	})
	require.Len(t, result.Packet, stepCount)
	for index := 0; index < stepCount; index++ {
		pair, ok := result.Packet[index]
		require.True(t, ok, "packet is missing step %d", index)
		require.Equal(t, fmt.Sprintf("request-step-%d", index), pair.Request)
		require.Equal(t, fmt.Sprintf("response-step-%d", index), pair.Response)
	}
}

func TestRecordHTTPExchangeHistoryPreservesSequentialEvidenceWithoutRequestCondition(t *testing.T) {
	previous := output.InternalEvent{}
	first := output.InternalEvent{}
	recordHTTPExchangeHistory(previous, first, output.InternalEvent{
		"request":  "POST /admin/login HTTP/1.1\r\n\r\nusername=probe",
		"response": "HTTP/1.1 302 Found\r\nSet-Cookie: session=redacted",
		"body":     "not retained without an explicit request condition",
	}, 0, false)

	second := output.InternalEvent{}
	for key, value := range previous {
		second[key] = value
	}
	recordHTTPExchangeHistory(previous, second, output.InternalEvent{
		"request":  "GET /admin/home HTTP/1.1\r\nCookie: session=redacted",
		"response": "HTTP/1.1 200 OK\r\n\r\nWelcome back",
		"body":     "Welcome back",
	}, 1, false)

	require.Equal(t, "POST /admin/login HTTP/1.1\r\n\r\nusername=probe", second["request_0"])
	require.Equal(t, "HTTP/1.1 302 Found\r\nSet-Cookie: session=redacted", second["response_0"])
	require.Equal(t, "GET /admin/home HTTP/1.1\r\nCookie: session=redacted", second["request_1"])
	require.Equal(t, "HTTP/1.1 200 OK\r\n\r\nWelcome back", second["response_1"])
	require.NotContains(t, second, "body_0")
	require.NotContains(t, second, "body_1")
}

func TestRecordHTTPExchangeHistoryKeepsConditionFields(t *testing.T) {
	previous := output.InternalEvent{}
	final := output.InternalEvent{}
	recordHTTPExchangeHistory(previous, final, output.InternalEvent{
		"request":  "GET / HTTP/1.1",
		"response": "HTTP/1.1 200 OK",
		"body":     "condition input",
	}, 3, true)

	require.Equal(t, "condition input", previous["body_3"])
	require.Equal(t, "condition input", final["body_3"])
}

func TestConcurrentHTTPExchangeHistoryUsesWorkerLocalClones(t *testing.T) {
	base := output.InternalEvent{"seed": "shared-read-only"}
	const workers = 64
	results := make(chan output.InternalEvent, workers)
	var wait sync.WaitGroup

	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			history := cloneHTTPEvent(base)
			final := cloneHTTPEvent(history)
			recordHTTPExchangeHistory(history, final, output.InternalEvent{
				"request":  fmt.Sprintf("request-%d", index),
				"response": fmt.Sprintf("response-%d", index),
			}, index, false)
			results <- final
		}(worker)
	}
	wait.Wait()
	close(results)

	require.Equal(t, output.InternalEvent{"seed": "shared-read-only"}, base)
	seen := make(map[int]struct{}, workers)
	for result := range results {
		for index := 0; index < workers; index++ {
			if result[fmt.Sprintf("request_%d", index)] == fmt.Sprintf("request-%d", index) {
				seen[index] = struct{}{}
				require.Equal(t, fmt.Sprintf("response-%d", index), result[fmt.Sprintf("response_%d", index)])
			}
		}
	}
	require.Len(t, seen, workers)
}

func TestSequentialRawRequestExecutionPreservesEveryExchangeWithoutRequestCondition(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/admin/login":
			require.Equal(t, http.MethodPost, request.Method)
			http.SetCookie(writer, &http.Cookie{Name: "argus_session", Value: "verified", Path: "/"})
			_, _ = writer.Write([]byte("login accepted"))
		case "/admin/home":
			require.Equal(t, http.MethodGet, request.Method)
			cookie, err := request.Cookie("argus_session")
			require.NoError(t, err)
			require.Equal(t, "verified", cookie.Value)
			_, _ = writer.Write([]byte("Welcome back Admin!"))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	templateID := "sequential-evidence-regression"
	request := &Request{
		ID: templateID,
		Raw: []string{
			"POST /admin/login HTTP/1.1\nHost: {{Hostname}}\nContent-Type: application/x-www-form-urlencoded\n\nusername=probe&password=probe",
			"GET /admin/home HTTP/1.1\nHost: {{Hostname}}\n\n",
		},
		CookieReuse: true,
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{
			Part:  "body",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"Welcome back Admin!"},
		}}},
	}
	require.False(t, request.NeedsRequestCondition())

	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: templateID,
		Info: model.Info{
			Name:           "Sequential evidence regression",
			SeverityHolder: severity.Holder{Severity: severity.Critical},
		},
	})
	require.NoError(t, request.Compile(executerOptions))

	var matched *output.InternalWrappedEvent
	err := request.ExecuteWithResults(
		contextargs.NewWithInput(server.URL),
		output.InternalEvent{},
		output.InternalEvent{},
		func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matched = event
			}
		},
	)
	require.NoError(t, err)
	require.NotNil(t, matched)

	packets := collectRequestResponsePackets(matched.InternalEvent)
	require.Len(t, packets, 2)
	require.Contains(t, packets[1].Request, "POST /admin/login")
	require.Contains(t, packets[1].Request, "username=probe&password=probe")
	require.Contains(t, packets[1].Response, "login accepted")
	require.Contains(t, packets[2].Request, "GET /admin/home")
	require.True(t, strings.Contains(packets[2].Request, "Cookie: argus_session=verified") || strings.Contains(packets[2].Request, "cookie: argus_session=verified"))
	require.Contains(t, packets[2].Response, "Welcome back Admin!")
}

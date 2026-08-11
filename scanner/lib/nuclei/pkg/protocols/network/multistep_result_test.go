package network

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

// TestNetworkMultiStepResultPreservesCompleteTransaction mirrors the four
// input/read sequence in the bundled CVE-2015-3306 ProFTPD fixture. Matchers
// use raw (the accumulated responses), and a successful ResultEvent must keep
// that same complete evidence instead of only the final data read.
func TestNetworkMultiStepResultPreservesCompleteTransaction(t *testing.T) {
	commands := []string{
		"site cpfr /proc/self/cmdline\r\n",
		"site cpto /tmp/.argus-report-test\r\n",
		"site cpfr /tmp/.argus-report-test\r\n",
		"site cpto /var/www/html/argus-report-test\r\n",
	}
	responses := []string{
		"350 File exists, ready for destination name step-1\r\n",
		"250 Copy successful step-2\r\n",
		"350 File exists, ready for destination name step-3\r\n",
		"250 Copy successful step-4\r\n",
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	serverErr := make(chan error, 1)
	go serveNetworkTransaction(listener, commands, responses, serverErr)

	options := testutils.DefaultOptions
	testutils.Init(options)
	templateID := "cve-2015-3306-multistep-regression"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Hostname}}"},
		ReadSize: 1024,
		Inputs: []*Input{
			{Data: commands[0], Read: 1024},
			{Data: commands[1], Read: 1024},
			{Data: commands[2], Read: 1024},
			{Data: commands[3]},
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "copy-successful",
				Part:  "raw",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"Copy successful step-4"},
			}},
		},
	}
	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: templateID,
		Info: model.Info{
			Name:           "ProFTPd multi-step evidence regression",
			SeverityHolder: severity.Holder{Severity: severity.Critical},
		},
	})
	require.NoError(t, request.Compile(executerOptions))

	var wrapped *output.InternalWrappedEvent
	err = request.ExecuteWithResults(
		contextargs.NewWithInput(listener.Addr().String()),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(event *output.InternalWrappedEvent) { wrapped = event },
	)
	require.NoError(t, err)
	select {
	case err := <-serverErr:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the synthetic ProFTPD transaction")
	}
	require.NotNil(t, wrapped)
	require.Len(t, wrapped.Results, 1)

	wantRequest := strings.Join(commands, "")
	wantResponse := strings.Join(responses, "")
	require.Equal(t, responses[len(responses)-1], wrapped.InternalEvent["data"], "data must retain its documented last-read semantics")
	require.Equal(t, wantResponse, wrapped.InternalEvent["raw"], "raw must contain every response read")
	require.Equal(t, wantRequest, wrapped.Results[0].Request, "ResultEvent must contain every request input")
	require.Equal(t, wantResponse, wrapped.Results[0].Response, "ResultEvent must contain every response read")
	for index, response := range responses {
		require.Contains(t, wrapped.Results[0].Response, response, "ResultEvent response is missing step %d", index+1)
	}
}

func serveNetworkTransaction(listener net.Listener, commands, responses []string, result chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		result <- err
		return
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	for index, command := range commands {
		got, readErr := reader.ReadString('\n')
		if readErr != nil {
			result <- fmt.Errorf("read command %d: %w", index+1, readErr)
			return
		}
		if got != command {
			result <- fmt.Errorf("command %d = %q, want %q", index+1, got, command)
			return
		}
		if _, writeErr := connection.Write([]byte(responses[index])); writeErr != nil {
			result <- fmt.Errorf("write response %d: %w", index+1, writeErr)
			return
		}
	}
	result <- nil
}

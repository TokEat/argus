package network

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

func TestNetworkResultPacketPreservesBinaryExchanges(t *testing.T) {
	requests := [][]byte{
		{0x00, 0xff, 0xfe, 'A'},
		{'B', 0xff, 0x00, 'C'},
	}
	responses := [][]byte{
		{0x10, 0x00, 0xff, 0xfe},
		{'D', 'O', 'N', 'E', 0x00, 0xff, 0xfe},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	serverErr := make(chan error, 1)
	go serveBinaryNetworkTransaction(listener, requests, responses, serverErr)

	options := testutils.DefaultOptions
	testutils.Init(options)
	templateID := "binary-multistep-packet-regression"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Hostname}}"},
		ReadSize: len(responses[1]),
		Inputs: []*Input{
			{
				Data: hex.EncodeToString(requests[0]),
				Type: NetworkInputTypeHolder{NetworkInputType: hexType},
				Read: len(responses[0]),
			},
			{Data: "{{hex_decode('42ff0043')}}"},
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "binary-success",
				Part:  "raw",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"DONE"},
			}},
		},
	}
	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: templateID,
		Info: model.Info{
			Name:           "Binary multi-step packet regression",
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
		t.Fatal("timed out waiting for the binary network transaction")
	}
	require.NotNil(t, wrapped)
	require.Len(t, wrapped.Results, 1)

	wantRaw := append(append([]byte{}, responses[0]...), responses[1]...)
	require.Equal(t, wantRaw, []byte(wrapped.InternalEvent["raw"].(string)), "raw matcher input must retain its existing byte-string semantics")
	require.Equal(t, responses[1], []byte(wrapped.InternalEvent["data"].(string)), "data must remain the final read")

	result := wrapped.Results[0]
	require.Len(t, result.Packet, len(requests))
	for index := range requests {
		pair, ok := result.Packet[index]
		require.True(t, ok, "packet is missing network step %d", index)
		require.Equal(t, hex.Dump(requests[index]), pair.Request, "packet request %d must represent the bytes written to TCP", index)
		require.Equal(t, hex.Dump(responses[index]), pair.Response, "packet response %d must represent the bytes read from TCP", index)
	}

	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	var decoded output.ResultEvent
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	for index := range requests {
		require.Equal(t, hex.Dump(requests[index]), decoded.Packet[index].Request, "JSON must preserve request evidence for step %d", index)
		require.Equal(t, hex.Dump(responses[index]), decoded.Packet[index].Response, "JSON must preserve response evidence for step %d", index)
	}
}

func TestAppendWrittenNetworkBytesRecordsOnlySuccessfulPrefix(t *testing.T) {
	payload := []byte{0x00, 0xff, 0xfe, 0x41}
	var recorded []byte

	appendWrittenNetworkBytes(&recorded, payload, 2)
	require.Equal(t, payload[:2], recorded)

	appendWrittenNetworkBytes(&recorded, payload, 0)
	appendWrittenNetworkBytes(&recorded, payload, -1)
	require.Equal(t, payload[:2], recorded, "zero or invalid write counts must not add unobserved bytes")
}

func TestMakeNetworkPacketSkipsUnobservedSteps(t *testing.T) {
	packet := makeNetworkPacket([]networkExchange{
		{},
		{request: []byte{0x00, 0xff}, response: []byte{0xfe}},
	})

	require.NotContains(t, packet, 0)
	require.Equal(t, hex.Dump([]byte{0x00, 0xff}), packet[1].Request)
	require.Equal(t, hex.Dump([]byte{0xfe}), packet[1].Response)
}

func serveBinaryNetworkTransaction(listener net.Listener, requests, responses [][]byte, result chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		result <- err
		return
	}
	defer connection.Close()

	for index, expectedRequest := range requests {
		actualRequest := make([]byte, len(expectedRequest))
		if _, err := io.ReadFull(connection, actualRequest); err != nil {
			result <- fmt.Errorf("read binary request %d: %w", index, err)
			return
		}
		if !bytes.Equal(actualRequest, expectedRequest) {
			result <- fmt.Errorf("binary request %d = %x, want %x", index, actualRequest, expectedRequest)
			return
		}
		if _, err := connection.Write(responses[index]); err != nil {
			result <- fmt.Errorf("write binary response %d: %w", index, err)
			return
		}
	}
	result <- nil
}

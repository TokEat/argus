package gopocs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestDNP3PublishesSuccessfulRawExchangeToBothSinks(t *testing.T) {
	request := mustDecodeProtocolHex(t, "056405060100000055c4")
	response := mustDecodeProtocolHex(t, "056405c001000000aabb")
	host, port, awaitServer := startProtocolEvidenceServer(t, []protocolExchangeFixture{{request: request, response: response}})

	capture, info := captureProtocolFindings(host, port)
	scanErr := DNP3Scan(info)
	awaitServer()
	if scanErr != nil {
		t.Fatal(scanErr)
	}

	want := []structs.GoPocExchange{
		binaryGoPocExchange("DNP3 link-layer read", request, response),
	}
	assertProtocolFindingEvidence(t, capture, "DNP3-Detect", want)
}

func TestDNP3DoesNotPublishEvidenceWhenResponseDoesNotMatch(t *testing.T) {
	request := mustDecodeProtocolHex(t, "056405060100000055c4")
	response := mustDecodeProtocolHex(t, "000005c001000000aabb")
	host, port, awaitServer := startProtocolEvidenceServer(t, []protocolExchangeFixture{{request: request, response: response}})

	capture, info := captureProtocolFindings(host, port)
	scanErr := DNP3Scan(info)
	awaitServer()
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	if len(capture.emitted) != 0 || len(capture.stored) != 0 {
		t.Fatalf("non-matching DNP3 response published evidence: emitted=%#v stored=%#v", capture.emitted, capture.stored)
	}
}

func TestS7PublishesOrderedSuccessfulRawExchangesToBothSinks(t *testing.T) {
	cotpRequest := mustDecodeProtocolHex(t, "0300001611e00000000100c0010ac1020100c2020102")
	cotpResponse := mustDecodeProtocolHex(t, "0300000b06d00000000100")
	setupRequest := mustDecodeProtocolHex(t, "0300001902f08032010000000000080000f0000001000101e0")
	setupResponse := mustDecodeProtocolHex(t, "0300001b02f080320300000000000800000000f0000001000101e0")
	host, port, awaitServer := startProtocolEvidenceServer(t, []protocolExchangeFixture{
		{request: cotpRequest, response: cotpResponse},
		{request: setupRequest, response: setupResponse},
	})

	capture, info := captureProtocolFindings(host, port)
	scanErr := S7Scan(info)
	awaitServer()
	if scanErr != nil {
		t.Fatal(scanErr)
	}

	want := []structs.GoPocExchange{
		binaryGoPocExchange("S7 COTP connection", cotpRequest, cotpResponse),
		binaryGoPocExchange("S7 setup communication", setupRequest, setupResponse),
	}
	assertProtocolFindingEvidence(t, capture, "S7-Detect", want)
}

func TestSingleStepICSScansPublishSuccessfulRawExchangeToBothSinks(t *testing.T) {
	tests := []struct {
		name     string
		pocName  string
		label    string
		request  string
		response string
		scan     func(*structs.HostInfo) error
	}{
		{name: "EtherNetIP", pocName: "EtherNetIP-Detect", label: "EtherNet/IP ListIdentity", request: "630000000000000000000000000000000000000000000000", response: "63000000", scan: EtherNetIPScan},
		{name: "ATG", pocName: "ATG-Detect", label: "ATG inventory command", request: "014932303130300a", response: "014f4b0a", scan: ATGScan},
		{name: "MELSEC", pocName: "MELSEC-Detect", label: "MELSEC-Q binary read", request: "5700000011000000000000ffff0300001c001008000000000000000000000104010001000000", response: "d7000000", scan: MELSECScan},
		{name: "FINS", pocName: "FINS-Detect", label: "FINS/TCP node address request", request: "46494e530000000c00000000000000000000000000", response: "46494e5300000000", scan: FINSScan},
		{name: "Crimson", pocName: "Crimson-Detect", label: "Crimson service probe", request: "00040116", response: "010203", scan: CrimsonScan},
		{name: "IEC104", pocName: "IEC104-Detect", label: "IEC-104 STARTDT activation", request: "680407000000", response: "68040b000000", scan: IEC104Scan},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := mustDecodeProtocolHex(t, test.request)
			response := mustDecodeProtocolHex(t, test.response)
			host, port, awaitServer := startProtocolEvidenceServer(t, []protocolExchangeFixture{{request: request, response: response}})
			capture, info := captureProtocolFindings(host, port)
			if err := test.scan(info); err != nil {
				t.Fatal(err)
			}
			awaitServer()
			assertProtocolFindingEvidence(t, capture, test.pocName, []structs.GoPocExchange{
				binaryGoPocExchange(test.label, request, response),
			})
		})
	}
}

func TestWMIAndNetBIOSEmittersKeepEvidenceConsistent(t *testing.T) {
	tests := []struct {
		name      string
		pocName   string
		exchanges []structs.GoPocExchange
		emit      func(*structs.HostInfo, []structs.GoPocExchange)
	}{
		{
			name:    "WMI",
			pocName: "WMI-Leak",
			exchanges: []structs.GoPocExchange{
				binaryGoPocExchange("WMI DCE/RPC bind", []byte{0x01}, []byte{0x02}),
				binaryGoPocExchange("WMI DCE/RPC host information query", []byte{0x03}, []byte{0x04}),
			},
			emit: func(info *structs.HostInfo, exchanges []structs.GoPocExchange) {
				emitFindnetFinding(info, "192.0.2.10", "192.0.2.10 TEST-HOST", exchanges)
			},
		},
		{
			name:    "NetBIOS",
			pocName: "NetBIOS-Leak",
			exchanges: []structs.GoPocExchange{
				binaryGoPocExchange("NetBIOS NBNS node status", []byte{0x05}, []byte{0x06}),
				binaryGoPocExchange("SMBv1 negotiate", []byte{0x07}, []byte{0x08}),
			},
			emit: func(info *structs.HostInfo, exchanges []structs.GoPocExchange) {
				emitNetBIOSFinding(info, "192.0.2.11:445", "NetBios: 192.0.2.11 TEST-HOST", "Host: 192.0.2.11:445", exchanges)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture, info := captureProtocolFindings("", "")
			test.emit(info, test.exchanges)
			assertProtocolFindingEvidence(t, capture, test.pocName, test.exchanges)
		})
	}
}

type protocolFindingCapture struct {
	emitted []structs.OutputMessage
	stored  []structs.GoPocsResultType
}

type protocolExchangeFixture struct {
	request  []byte
	response []byte
}

func startProtocolEvidenceServer(t *testing.T, fixtures []protocolExchangeFixture) (host, port string, await func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serverErr := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		for index, fixture := range fixtures {
			request := make([]byte, len(fixture.request))
			if _, readErr := io.ReadFull(connection, request); readErr != nil {
				serverErr <- fmt.Errorf("read request %d: %w", index+1, readErr)
				return
			}
			if !bytes.Equal(request, fixture.request) {
				serverErr <- fmt.Errorf("request %d = %x, want %x", index+1, request, fixture.request)
				return
			}
			if _, writeErr := connection.Write(fixture.response); writeErr != nil {
				serverErr <- fmt.Errorf("write response %d: %w", index+1, writeErr)
				return
			}
		}
		serverErr <- nil
	}()

	host, port, err = net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return host, port, func() {
		t.Helper()
		select {
		case err := <-serverErr:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("protocol evidence server did not finish")
		}
	}
}

func captureProtocolFindings(host, port string) (*protocolFindingCapture, *structs.HostInfo) {
	capture := &protocolFindingCapture{}
	info := &structs.HostInfo{
		Host:  host,
		Ports: port,
		Emit: func(message structs.OutputMessage) {
			capture.emitted = append(capture.emitted, message)
		},
		WriteResult: func(result structs.GoPocsResultType) {
			capture.stored = append(capture.stored, result)
		},
	}
	return capture, info
}

func assertProtocolFindingEvidence(t *testing.T, capture *protocolFindingCapture, pocName string, want []structs.GoPocExchange) {
	t.Helper()
	if len(capture.emitted) != 1 || len(capture.stored) != 1 {
		t.Fatalf("finding copies = emitted:%d stored:%d, want one each", len(capture.emitted), len(capture.stored))
	}
	if capture.emitted[0].GoPoc.PocName != pocName {
		t.Fatalf("emitted POC = %q, want %q", capture.emitted[0].GoPoc.PocName, pocName)
	}
	if capture.stored[0].PocName != pocName {
		t.Fatalf("stored POC = %q, want %q", capture.stored[0].PocName, pocName)
	}
	if !reflect.DeepEqual(capture.emitted[0].GoPoc.Exchanges, want) {
		t.Fatalf("emitted exchanges = %#v, want %#v", capture.emitted[0].GoPoc.Exchanges, want)
	}
	if !reflect.DeepEqual(capture.stored[0].Exchanges, want) {
		t.Fatalf("stored exchanges = %#v, want %#v", capture.stored[0].Exchanges, want)
	}
}

func mustDecodeProtocolHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

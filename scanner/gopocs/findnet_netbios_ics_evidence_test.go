package gopocs

import (
	"reflect"
	"testing"

	"github.com/TokEat/argus/scanner/structs"
)

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

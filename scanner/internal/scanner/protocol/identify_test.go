package protocol

import (
	"strings"
	"sync"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/lcvvvv/gonmap"
)

func TestHandleResultStoresCanonicalServiceAndProduct(t *testing.T) {
	var emitted []structs.OutputMessage
	rt := NewRuntime(map[string]string{}, &sync.Mutex{}, nil, func(message structs.OutputMessage) {
		emitted = append(emitted, message)
	}, map[string]structs.ServiceRecord{})

	rt.handleResult(protocolResult{
		IP:     "10.0.0.8",
		Port:   445,
		Status: int(gonmap.Matched),
		Response: &gonmap.Response{
			Raw: "smb-banner",
			FingerPrint: &gonmap.FingerPrint{
				Service:         "microsoft-ds",
				ProductName:     "Microsoft Windows SMB",
				Version:         "3.1.1",
				Info:            "workgroup: CORP",
				Hostname:        "DC01",
				OperatingSystem: "Windows",
			},
		},
	})

	got := rt.IPPortMap["10.0.0.8:445"]
	if got != "smb" {
		t.Fatalf("stored protocol = %q, want smb", got)
	}
	record := rt.ServiceMap["10.0.0.8:445"]
	if record.Product != "Microsoft Windows SMB" || record.Version != "3.1.1" || record.Confidence != "matched" {
		t.Fatalf("service record = %+v", record)
	}
	if !strings.Contains(record.Extra, "host=DC01") || !strings.Contains(record.Extra, "workgroup=CORP") || !strings.Contains(record.Extra, "os=Windows") {
		t.Fatalf("missing service extras: %+v", record)
	}
	if len(emitted) != 1 || emitted[0].Type != "PortScan" || emitted[0].Protocol != "smb" || emitted[0].Product != "Microsoft Windows SMB" || emitted[0].Version != "3.1.1" {
		t.Fatalf("emitted = %+v", emitted)
	}
	if !strings.Contains(emitted[0].AdditionalMsg, "host=DC01") || !strings.Contains(emitted[0].AdditionalMsg, "workgroup=CORP") {
		t.Fatalf("emitted extras = %q", emitted[0].AdditionalMsg)
	}
}

func TestHandleResultOpenPortStaysTCPExceptTelnetHint(t *testing.T) {
	rt := NewRuntime(map[string]string{}, &sync.Mutex{}, nil, nil, map[string]structs.ServiceRecord{})
	rt.handleResult(protocolResult{IP: "10.0.0.8", Port: 2222, Status: int(gonmap.Open)})
	rt.handleResult(protocolResult{IP: "10.0.0.8", Port: 23, Status: int(gonmap.Open)})
	if rt.IPPortMap["10.0.0.8:2222"] != "tcp" {
		t.Fatalf("open unknown port = %q", rt.IPPortMap["10.0.0.8:2222"])
	}
	if rt.IPPortMap["10.0.0.8:23"] != "telnet" || rt.ServiceMap["10.0.0.8:23"].Confidence != "port-hint" {
		t.Fatalf("telnet hint = %+v", rt.ServiceMap["10.0.0.8:23"])
	}
}

func TestStoreRecordUDPDoesNotEnterIPPortMap(t *testing.T) {
	rt := NewRuntime(map[string]string{}, &sync.Mutex{}, nil, nil, map[string]structs.ServiceRecord{})
	rt.storeRecord(structs.ServiceRecord{
		Endpoint:   "10.0.0.8:53",
		Transport:  "udp",
		Protocol:   "dns",
		Product:    "DNS",
		Confidence: "enriched",
	})
	if _, ok := rt.IPPortMap["10.0.0.8:53"]; ok {
		t.Fatalf("udp record leaked into IPPortMap: %#v", rt.IPPortMap)
	}
	got := rt.ServiceMap["10.0.0.8:53/udp"]
	if got.Protocol != "dns" || got.Transport != "udp" {
		t.Fatalf("service map = %+v", got)
	}
}

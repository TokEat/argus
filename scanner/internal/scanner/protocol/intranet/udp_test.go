package intranet

import (
	"net"
	"testing"
	"time"
)

func TestClassifyUDPFirstWave(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "dns", raw: []byte{0x00, 0x06, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}, want: "dns"},
		{name: "ntp", raw: ntpServerReply(), want: "ntp"},
		{name: "snmp", raw: []byte{0x30, 0x0a, 0x02, 0x01, 0x00}, want: "snmp"},
		{name: "sip", raw: []byte("SIP/2.0 200 OK\r\n\r\n"), want: "sip"},
		{name: "ssdp", raw: []byte("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:1\r\n\r\n"), want: "ssdp"},
		{name: "isakmp", raw: ikeReply(), want: "isakmp"},
		{name: "kerberos", raw: []byte{0x7e, 0x03, 0x00, 0x00, 0x00, 0x00}, want: "kerberos"},
		{name: "mdns", raw: []byte{0x00, 0x00, 0x84, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, '_', 'u', 'd', 'p', '.', 'l', 'o', 'c', 'a', 'l'}, want: "mdns"},
		{name: "netbios-ns", raw: []byte{0x80, 0xf0, 0x80, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}, want: "netbios-ns"},
	}
	for _, tc := range cases {
		rec, ok := ClassifyUDP(tc.name, tc.raw)
		if !ok || rec.Protocol != tc.want || rec.Transport != "udp" {
			t.Fatalf("%s => %+v ok=%v want %s/udp", tc.name, rec, ok, tc.want)
		}
	}
}

func TestClassifyUDPRejectsNoise(t *testing.T) {
	if rec, ok := ClassifyUDP("dns", []byte{0x00, 0x01, 0x01, 0x00}); ok {
		t.Fatalf("short query classified as %+v", rec)
	}
	if rec, ok := ClassifyUDP("ntp", []byte{0x24}); ok {
		t.Fatalf("short ntp classified as %+v", rec)
	}
	if rec, ok := ClassifyUDP("sip", []byte("HTTP/1.1 200 OK\r\n\r\n")); ok {
		t.Fatalf("http classified as sip: %+v", rec)
	}
	if rec, ok := ClassifyUDP("unknown", []byte{0x30, 0x01}); ok {
		t.Fatalf("unknown probe classified as %+v", rec)
	}
}

func TestDefaultUDPProbesFirstWave(t *testing.T) {
	want := map[string]int{
		"dns": 53, "kerberos": 88, "ntp": 123, "netbios-ns": 137,
		"snmp": 161, "isakmp": 500, "ssdp": 1900, "sip": 5060, "mdns": 5353,
	}
	got := DefaultUDPProbes()
	if len(got) != len(want) {
		t.Fatalf("probe count = %d want %d", len(got), len(want))
	}
	seen := map[string]int{}
	for _, probe := range got {
		seen[probe.Name] = probe.Port
		if len(probe.Payloads) == 0 {
			t.Fatalf("%s has no payloads", probe.Name)
		}
	}
	for name, port := range want {
		if seen[name] != port {
			t.Fatalf("%s port = %d want %d", name, seen[name], port)
		}
	}
}

func TestLiveUDPProbes(t *testing.T) {
	type spec struct {
		name  string
		reply []byte
		probe UDPProbe
	}
	specs := []spec{
		{name: "dns", reply: []byte{0x00, 0x06, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}, probe: UDPProbe{Name: "dns", Payloads: [][]byte{dnsVersionBindUDP()}}},
		{name: "ntp", reply: ntpServerReply(), probe: UDPProbe{Name: "ntp", Payloads: [][]byte{ntpRequest()}}},
		{name: "snmp", reply: []byte{0x30, 0x0c, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c'}, probe: UDPProbe{Name: "snmp", Payloads: [][]byte{snmpV1GetSysName()}}},
		{name: "sip", reply: []byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), probe: UDPProbe{Name: "sip", Payloads: [][]byte{sipOptions()}}},
		{name: "ssdp", reply: []byte("HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1/desc.xml\r\nST: ssdp:all\r\n\r\n"), probe: UDPProbe{Name: "ssdp", Payloads: [][]byte{ssdpSearch()}}},
		{name: "isakmp", reply: ikeReply(), probe: UDPProbe{Name: "isakmp", Payloads: [][]byte{ikeMainMode()}}},
		{name: "kerberos", reply: []byte{0x7e, 0x03, 0x00, 0x00, 0x00, 0x00}, probe: UDPProbe{Name: "kerberos", Payloads: [][]byte{kerberosASREQUDP()}}},
		{name: "mdns", reply: []byte{0x00, 0x00, 0x84, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, '_', 'u', 'd', 'p', '.', 'l', 'o', 'c', 'a', 'l'}, probe: UDPProbe{Name: "mdns", Payloads: [][]byte{dnsSDQuery()}}},
		{name: "netbios-ns", reply: []byte{0x80, 0xf0, 0x80, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}, probe: UDPProbe{Name: "netbios-ns", Payloads: [][]byte{nbstatQuery()}}},
	}
	for _, s := range specs {
		s := s
		t.Run(s.name, func(t *testing.T) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			port := pc.LocalAddr().(*net.UDPAddr).Port
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 4096)
				_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
				n, addr, err := pc.ReadFrom(buf)
				if err != nil || n == 0 {
					return
				}
				_, _ = pc.WriteTo(s.reply, addr)
			}()
			s.probe.Port = port
			rec, ok := ProbeUDP("127.0.0.1", s.probe, 2*time.Second)
			<-done
			if !ok || rec.Protocol != s.name || rec.Transport != "udp" {
				t.Fatalf("got %+v ok=%v want %s/udp", rec, ok, s.name)
			}
		})
	}
}

func TestUDPClosedPortIsNotIdentified(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	rec, ok := ProbeUDP("127.0.0.1", UDPProbe{Name: "dns", Port: port, Payloads: [][]byte{dnsVersionBindUDP()}}, 200*time.Millisecond)
	if ok {
		t.Fatalf("closed udp port produced %+v", rec)
	}
}

func ntpServerReply() []byte {
	p := make([]byte, 48)
	p[0] = 0x24 // VN=4 Mode=4 server
	return p
}

func ikeReply() []byte {
	p := make([]byte, 32)
	p[17] = 0x10
	p[18] = 4
	return p
}

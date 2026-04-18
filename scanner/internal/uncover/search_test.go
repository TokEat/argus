package uncover

import (
	"dddd/scanner/structs"
	"reflect"
	"testing"
)

func TestAddIPDomainMapDedupes(t *testing.T) {
	state := &State{
		IPDomainMap: map[string][]string{},
	}

	addIPDomainMap(state, "1.1.1.1", "a.example.com")
	addIPDomainMap(state, "1.1.1.1", "a.example.com")
	addIPDomainMap(state, "1.1.1.1", "b.example.com")

	want := []string{"a.example.com", "b.example.com"}
	if !reflect.DeepEqual(state.IPDomainMap["1.1.1.1"], want) {
		t.Fatalf("unexpected domain map: want=%v got=%v", want, state.IPDomainMap["1.1.1.1"])
	}
}

func TestStoreHunterServiceAndWeb(t *testing.T) {
	state := &State{
		IPPortMap: map[string]string{},
		URLMap:    map[string]structs.URLEntity{},
	}

	storeHunterService(state, hunterInfo{
		IP:       "1.1.1.1",
		Port:     22,
		Protocol: "ssh",
		Banner:   "SSH-2.0-test",
	})
	if got := state.IPPortMap["1.1.1.1:22"]; got != "ssh" {
		t.Fatalf("unexpected service map entry: %q", got)
	}

	storeHunterWeb(state, hunterInfo{
		IP:       "2.2.2.2",
		Port:     443,
		Protocol: "https",
		Title:    "Example",
		Banner:   "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello",
	})

	entry, ok := state.URLMap["https://2.2.2.2:443"]
	if !ok {
		t.Fatalf("expected hunter web entry to be stored")
	}
	root, ok := entry.WebPaths["/"]
	if !ok {
		t.Fatalf("expected root path to be stored")
	}
	if root.Title != "Example" || root.StatusCode != 200 || root.Server != "nginx" {
		t.Fatalf("unexpected web path entity: %#v", root)
	}
}

func TestBuildFOFATarget(t *testing.T) {
	target, show := buildFOFATarget("demo.example.com:8443", "https", "1.1.1.1", "8443", "demo.example.com", "Demo", "ICP", false, Config{})
	if target != "demo.example.com:8443" {
		t.Fatalf("unexpected target: %q", target)
	}
	if show == "" {
		t.Fatalf("expected show string to be populated")
	}

	target, _ = buildFOFATarget("demo.example.com:8443", "https", "1.1.1.1", "8443", "demo.example.com", "", "", false, Config{OnlyIPPort: true})
	if target != "https://1.1.1.1:8443" {
		t.Fatalf("unexpected ip-port target: %q", target)
	}
}

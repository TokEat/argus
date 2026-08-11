package gopocs

import (
	"reflect"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestTelnetBypassFindingPublishesVerificationExchange(t *testing.T) {
	want := []structs.GoPocExchange{
		binaryGoPocExchange("Telnet environment bypass and root-shell verification", []byte("exploit\nid\n"), []byte("uid=0(root) gid=0(root)")),
	}
	var emitted structs.OutputMessage
	var stored structs.GoPocsResultType
	info := &structs.HostInfo{
		Host:  "127.0.0.1",
		Ports: "23",
		Emit: func(message structs.OutputMessage) {
			emitted = message
		},
		WriteResult: func(result structs.GoPocsResultType) {
			stored = result
		},
	}

	reportVulnerability(info, "ID Command Output: uid=0(root)", want)
	if !reflect.DeepEqual(emitted.GoPoc.Exchanges, want) {
		t.Fatalf("emitted exchanges = %#v, want %#v", emitted.GoPoc.Exchanges, want)
	}
	if !reflect.DeepEqual(stored.Exchanges, want) {
		t.Fatalf("stored exchanges = %#v, want %#v", stored.Exchanges, want)
	}
}

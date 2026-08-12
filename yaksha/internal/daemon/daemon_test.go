package daemon

import (
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/yaksha/internal/egress"
	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
)

func TestSelectedEgress(t *testing.T) {
	t.Run("direct is explicit", func(t *testing.T) {
		client, err := selectedEgress(protocol.Request{Egress: &protocol.EgressConfig{Mode: protocol.EgressDirect}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := client.(egress.NetworkClient); !ok {
			t.Fatalf("client=%T, want NetworkClient", client)
		}
	})

	t.Run("missing mode fails closed", func(t *testing.T) {
		client, err := selectedEgress(protocol.Request{})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := client.(egress.DisabledClient); !ok {
			t.Fatalf("client=%T, want DisabledClient", client)
		}
	})

	t.Run("test always disables network", func(t *testing.T) {
		client, err := selectedEgress(protocol.Request{Action: protocol.ActionTest, Egress: &protocol.EgressConfig{Mode: protocol.EgressDirect}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := client.(egress.DisabledClient); !ok {
			t.Fatalf("client=%T, want DisabledClient", client)
		}
	})

	t.Run("relay is reserved without fallback", func(t *testing.T) {
		_, err := selectedEgress(protocol.Request{Egress: &protocol.EgressConfig{Mode: protocol.EgressRelay, RouteID: "route-1"}})
		if err == nil || !strings.Contains(err.Error(), "Agent Egress Unavailable") {
			t.Fatalf("error=%v", err)
		}
	})
}

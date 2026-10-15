package discovery

import (
	"net"
	"reflect"
	"testing"
)

func testLinkNet(cidr, src string) LinkNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return LinkNet{
		Iface: net.Interface{Name: "test0", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}},
		SrcIP: net.ParseIP(src).To4(),
		Net:   ipnet,
	}
}

func TestPartitionOnLinkAndOffLink(t *testing.T) {
	nets := []LinkNet{testLinkNet("10.0.0.0/24", "10.0.0.8")}
	on, off := Partition([]string{"10.0.0.1", "10.0.1.1", "192.0.2.1", "not-an-ip"}, nets)
	if !reflect.DeepEqual(on, []string{"10.0.0.1"}) {
		t.Fatalf("on-link = %v", on)
	}
	if !reflect.DeepEqual(off, []string{"10.0.1.1", "192.0.2.1", "not-an-ip"}) {
		t.Fatalf("off-link = %v", off)
	}
}

func TestPartitionEmptyNetsAreOffLink(t *testing.T) {
	on, off := Partition([]string{"10.0.0.1"}, nil)
	if len(on) != 0 || !reflect.DeepEqual(off, []string{"10.0.0.1"}) {
		t.Fatalf("on=%v off=%v", on, off)
	}
}

func TestGroupByNetFirstMatchWins(t *testing.T) {
	nets := []LinkNet{
		testLinkNet("10.0.0.0/24", "10.0.0.8"),
		testLinkNet("10.1.0.0/24", "10.1.0.8"),
	}
	groups := GroupByNet([]string{"10.1.0.2", "10.0.0.3", "8.8.8.8"}, nets)
	if len(groups) != 2 {
		t.Fatalf("groups = %#v", groups)
	}
	if !reflect.DeepEqual(groups[0], []string{"10.0.0.3"}) || !reflect.DeepEqual(groups[1], []string{"10.1.0.2"}) {
		t.Fatalf("groups = %#v", groups)
	}
}

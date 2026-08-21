package discovery

import (
	"reflect"
	"testing"
)

func TestDifferenceAndUnion(t *testing.T) {
	got := Difference([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, []string{"10.0.0.2"})
	if !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.3"}) {
		t.Fatalf("difference = %v", got)
	}
	if !reflect.DeepEqual(Union([]string{"10.0.0.2"}, []string{"10.0.0.1", "10.0.0.2"}), []string{"10.0.0.2", "10.0.0.1"}) {
		t.Fatalf("union = %v", Union([]string{"10.0.0.2"}, []string{"10.0.0.1", "10.0.0.2"}))
	}
}

func TestHostsFromIPPorts(t *testing.T) {
	got := HostsFromIPPorts([]string{"10.0.0.1:80", "10.0.0.1:443", "10.0.0.2:445", "bad"})
	if !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("hosts = %v", got)
	}
}

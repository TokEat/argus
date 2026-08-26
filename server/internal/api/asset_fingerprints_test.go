package api

import (
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
)

func TestEndpointIdentityNormalizesWebTargets(t *testing.T) {
	if got := endpointIdentity("https://web.example"); got != "web.example|443" {
		t.Fatalf("https identity=%q", got)
	}
	if got := endpointIdentity("https://web.example:443/jenkins/login"); got != "web.example|443" {
		t.Fatalf("path identity=%q", got)
	}
}

func TestRelatedHostsForSwapsDomainAndIP(t *testing.T) {
	resolutions := []assetResolution{{Domain: "assoc.test", IPs: []string{"198.51.100.9"}}}
	fromDomain := relatedHostsFor("assoc.test", resolutions)
	if len(fromDomain) != 1 || fromDomain[0] != "198.51.100.9" {
		t.Fatalf("domain related=%v", fromDomain)
	}
	fromIP := relatedHostsFor("198.51.100.9", resolutions)
	if len(fromIP) != 1 || fromIP[0] != "assoc.test" {
		t.Fatalf("ip related=%v", fromIP)
	}
}

func TestAssetEndpointIdentitiesIncludesResolvedHosts(t *testing.T) {
	identities := assetEndpointIdentities(
		db.Asset{Target: "https://assoc.test", Protocol: "Web"},
		[]assetResolution{{Domain: "assoc.test", IPs: []string{"198.51.100.9"}}},
	)
	want := map[string]bool{"assoc.test|443": true, "198.51.100.9|443": true}
	for _, identity := range identities {
		delete(want, identity)
	}
	if len(want) != 0 {
		t.Fatalf("missing identities %v from %v", want, identities)
	}
}

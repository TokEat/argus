package subdomain

import (
	"slices"
	"testing"

	"github.com/P0lar1ght/argus/scanner/ddout"
)

func TestEnumerateExpandsOnlyResolvedFrontierToRequestedDepth(t *testing.T) {
	original := runDNSBruteforce
	t.Cleanup(func() { runDNSBruteforce = original })

	var parents []string
	runDNSBruteforce = func(parent string, _ int, callback func(string), words []string, _ string) []string {
		parents = append(parents, parent)
		if !slices.Contains(words, "projectword") || len(words) <= 1 {
			t.Fatalf("wordlist did not combine built-in and project words: %v", words)
		}
		found := map[string][]string{
			"example.test":       {"a.example.test"},
			"a.example.test":     {"b.a.example.test"},
			"b.a.example.test":   {"c.b.a.example.test"},
			"c.b.a.example.test": {"unexpected.example.test"},
		}[parent]
		for _, value := range found {
			callback(value)
		}
		return found
	}

	got := Enumerate([]string{"example.test"}, Config{
		NoSubFinder: true, SubdomainBruteforceDepth: 3,
		SubdomainDictionaryWords: []string{"ProjectWord", "projectword"},
	})
	want := []string{"a.example.test", "b.a.example.test", "c.b.a.example.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("results = %v, want %v", got, want)
	}
	if wantParents := []string{"example.test", "a.example.test", "b.a.example.test"}; !slices.Equal(parents, wantParents) {
		t.Fatalf("parents = %v, want %v", parents, wantParents)
	}
}

func TestEnumerateStopsWhenAResolvedFrontierIsEmpty(t *testing.T) {
	original := runDNSBruteforce
	t.Cleanup(func() { runDNSBruteforce = original })

	calls := 0
	runDNSBruteforce = func(_ string, _ int, _ func(string), _ []string, _ string) []string {
		calls++
		return nil
	}
	if got := Enumerate([]string{"example.test"}, Config{NoSubFinder: true, SubdomainBruteforceDepth: 4}); len(got) != 0 {
		t.Fatalf("results = %v, want none", got)
	}
	if calls != 1 {
		t.Fatalf("DNS brute calls = %d, want 1", calls)
	}
}

func TestMergeWordlistsNormalizesAndDeduplicates(t *testing.T) {
	got := mergeWordlists([]string{"WWW", "api"}, []string{" www ", ".DEV.", ""})
	for _, value := range []string{"www", "api", "dev"} {
		if !slices.Contains(got, value) {
			t.Fatalf("merged wordlist missing %q: %v", value, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("merged wordlist = %v, want 3 unique entries", got)
	}
}

func TestEnumerateMergesServerInjectedResultsWithoutSubfinder(t *testing.T) {
	original := runDNSBruteforce
	t.Cleanup(func() { runDNSBruteforce = original })
	runDNSBruteforce = func(_ string, _ int, _ func(string), _ []string, _ string) []string {
		return []string{"brute.example.test", "api.example.test"}
	}

	var emitted []ddout.OutputMessage
	got := Enumerate([]string{"example.test"}, Config{
		NoSubFinder: true,
		Injected: map[string][]string{
			"example.test": {"api.example.test", "injected.example.test"},
		},
		EmitFunc: func(msg ddout.OutputMessage) { emitted = append(emitted, msg) },
	})

	want := []string{"brute.example.test", "api.example.test", "injected.example.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("results = %v, want %v", got, want)
	}
	var injectedMessages []ddout.OutputMessage
	for _, msg := range emitted {
		if msg.Type == "DNS-SubFinder" && msg.AdditionalMsg == "server-passive" {
			injectedMessages = append(injectedMessages, msg)
		}
	}
	if len(injectedMessages) != 2 {
		t.Fatalf("server-passive emissions = %d, want 2", len(injectedMessages))
	}
}

func TestEnumerateInjectedDomainSkipsSubfinderEvenWhenEnabled(t *testing.T) {
	original := runDNSBruteforce
	t.Cleanup(func() { runDNSBruteforce = original })
	runDNSBruteforce = func(_ string, _ int, _ func(string), _ []string, _ string) []string {
		return nil
	}

	// NoSubFinder=false would normally run subFinder (network); the injected
	// entry for the covered domain must prevent that. The uncovered domain
	// stays on the subfinder path, so this test only feeds the covered one.
	got := Enumerate([]string{"example.test"}, Config{
		NoSubFinder: false,
		Injected:    map[string][]string{"example.test": {"api.example.test"}},
	})
	if !slices.Equal(got, []string{"api.example.test"}) {
		t.Fatalf("results = %v, want injected list only", got)
	}
}

func TestEnumerateEmptyInjectedListStillSkipsSubfinder(t *testing.T) {
	original := runDNSBruteforce
	t.Cleanup(func() { runDNSBruteforce = original })
	runDNSBruteforce = func(_ string, _ int, _ func(string), _ []string, _ string) []string {
		return nil
	}

	got := Enumerate([]string{"example.test"}, Config{
		NoSubFinder: false,
		Injected:    map[string][]string{"example.test": nil},
	})
	if len(got) != 0 {
		t.Fatalf("results = %v, want none", got)
	}
}

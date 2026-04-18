package subdomain

import "testing"

func TestRemoveEmpty(t *testing.T) {
	got := removeEmpty([]string{"a.example.com", "", " ", "b.example.com"})
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Fatalf("unexpected cleaned list: %#v", got)
	}
}

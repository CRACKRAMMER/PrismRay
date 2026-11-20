// SPDX-License-Identifier: MPL-2.0

package androiddns

import (
	"reflect"
	"testing"
)

func TestParseAndNormalizeServers(t *testing.T) {
	got := ParseServerList("192.168.1.1, 127.0.0.1, ::1, 223.5.5.5:53, [2001:4860:4860::8888]:53, 192.168.1.1, invalid")
	want := []string{
		"192.168.1.1:53",
		"223.5.5.5:53",
		"[2001:4860:4860::8888]:53",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseServerList mismatch:\ngot:  %v\nwant: %v", got, want)
	}
}

func TestActiveServersPrefersSystemThenFallbacks(t *testing.T) {
	defer SetSystemServers(nil)
	SetSystemServers([]string{"10.0.0.1", "223.5.5.5"})
	got := ActiveServers()
	if len(got) < 4 {
		t.Fatalf("expected system + fallback servers, got %v", got)
	}
	if got[0] != "10.0.0.1:53" || got[1] != "223.5.5.5:53" {
		t.Fatalf("expected system DNS first, got %v", got)
	}
	// Ensure no duplicates.
	seen := map[string]bool{}
	for _, s := range got {
		if seen[s] {
			t.Fatalf("duplicate DNS server %s in %v", s, got)
		}
		seen[s] = true
	}
}

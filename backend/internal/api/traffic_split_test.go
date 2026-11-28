// SPDX-License-Identifier: MPL-2.0

package api

import (
	"testing"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/clashapi"
)

func TestIsDirectChain(t *testing.T) {
	cases := []struct {
		name   string
		chains []string
		want   bool
	}{
		{"plain direct", []string{"direct"}, true},
		{"uppercase DIRECT", []string{"DIRECT"}, true},
		{"selector routing to direct", []string{"direct", "proxy"}, true},
		{"proxy node via group", []string{"node-us-1", "group-us", "proxy"}, false},
		{"tailscale endpoint", []string{"tailscale-ep"}, false},
		{"xray bridge", []string{"xray-bridge-1", "proxy"}, false},
		{"block outbound", []string{"block-out"}, false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDirectChain(tc.chains); got != tc.want {
				t.Fatalf("isDirectChain(%v) = %v, want %v", tc.chains, got, tc.want)
			}
		})
	}
}

func TestTrafficSplitTrackerMixedAndReconciliation(t *testing.T) {
	tracker := newTrafficSplitTracker(15 * time.Second)
	t0 := time.Unix(1700000000, 0)

	// Initial baseline must emit zeros without spiking on historical totals.
	r0 := tracker.Update(&clashapi.ConnectionsSnapshot{
		UploadTotal:   50000,
		DownloadTotal: 200000,
		Connections: []clashapi.ConnectionItem{
			{ID: "c-proxy", Upload: 10000, Download: 80000, Chains: []string{"node-hk", "group-hk"}},
			{ID: "c-direct", Upload: 5000, Download: 20000, Chains: []string{"direct"}},
		},
	}, t0, nil)
	if r0.Up != 0 || r0.Down != 0 || r0.ProxyUp != 0 || r0.DirectDown != 0 {
		t.Fatalf("expected zero baseline rates, got %+v", r0)
	}

	// 1 second later: proxy +1000/+4000, direct +500/+2000, plus new proxy conn +200/+800.
	t1 := t0.Add(1 * time.Second)
	r1 := tracker.Update(&clashapi.ConnectionsSnapshot{
		UploadTotal:   51700,  // delta = 1700 (exact match)
		DownloadTotal: 206800, // delta = 6800 (exact match)
		Connections: []clashapi.ConnectionItem{
			{ID: "c-proxy", Upload: 11000, Download: 84000, Chains: []string{"node-hk", "group-hk"}},
			{ID: "c-direct", Upload: 5500, Download: 22000, Chains: []string{"direct"}},
			{ID: "c-proxy-new", Upload: 200, Download: 800, Chains: []string{"tailscale-ep"}},
		},
	}, t1, nil)
	if r1.ProxyUp != 1200 || r1.ProxyDown != 4800 {
		t.Fatalf("unexpected proxy rates: %+v", r1)
	}
	if r1.DirectUp != 500 || r1.DirectDown != 2000 {
		t.Fatalf("unexpected direct rates: %+v", r1)
	}
	if r1.Up != 1700 || r1.Down != 6800 {
		t.Fatalf("unexpected total rates: %+v", r1)
	}

	// 2 seconds later: all active connections closed, short-lived traffic produced +1000/+2000.
	// With defaultDirect=true, remainder should attribute to direct and average over 2s.
	t2 := t1.Add(2 * time.Second)
	r2 := tracker.Update(&clashapi.ConnectionsSnapshot{
		UploadTotal:   52700,  // delta = 1000 over 2s -> 500 B/s
		DownloadTotal: 208800, // delta = 2000 over 2s -> 1000 B/s
		Connections:   nil,
	}, t2, func() bool { return true })
	if r2.DirectUp != 500 || r2.DirectDown != 1000 || r2.ProxyUp != 0 || r2.ProxyDown != 0 {
		t.Fatalf("expected short-lived fallback to direct (500/1000), got %+v", r2)
	}
	if len(tracker.conns) != 0 {
		t.Fatalf("expected closed connections to be pruned, still tracking %d", len(tracker.conns))
	}

	// After stale gap (> 15s, e.g. screen-off wake), tracker resets baseline with zero spike.
	t3 := t2.Add(30 * time.Second)
	r3 := tracker.Update(&clashapi.ConnectionsSnapshot{
		UploadTotal:   999999,
		DownloadTotal: 8888888,
		Connections: []clashapi.ConnectionItem{
			{ID: "c-after-wake", Upload: 50000, Download: 100000, Chains: []string{"node-jp"}},
		},
	}, t3, nil)
	if r3.Up != 0 || r3.Down != 0 {
		t.Fatalf("expected zero spike after stale gap, got %+v", r3)
	}

	// Counter reset (sing-box restarted) must also emit zero baseline without negative rates.
	t4 := t3.Add(1 * time.Second)
	r4 := tracker.Update(&clashapi.ConnectionsSnapshot{
		UploadTotal:   100,
		DownloadTotal: 200,
		Connections:   nil,
	}, t4, nil)
	if r4.Up != 0 || r4.Down != 0 {
		t.Fatalf("expected zero after counter reset, got %+v", r4)
	}
}

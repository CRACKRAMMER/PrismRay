// SPDX-License-Identifier: MPL-2.0

package api

import (
	"math"
	"strings"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/clashapi"
)

// TrafficRates carries per-second throughput split into proxy and direct paths,
// while keeping aggregate Up/Down for backward compatibility.
type TrafficRates struct {
	Up                int64 `json:"up"`
	Down              int64 `json:"down"`
	ProxyUp           int64 `json:"proxy_up"`
	ProxyDown         int64 `json:"proxy_down"`
	DirectUp          int64 `json:"direct_up"`
	DirectDown        int64 `json:"direct_down"`
	ActiveConnections int   `json:"active_connections"`
	Timestamp         int64 `json:"timestamp"`
}

type trafficSplitDeltas struct {
	proxyUp    int64
	proxyDown  int64
	directUp   int64
	directDown int64
}

type connByteCounter struct {
	up     int64
	down   int64
	direct bool
}

// trafficSplitTracker derives real-time direct vs. proxy upload/download rates
// from periodic Clash API /connections snapshots.
type trafficSplitTracker struct {
	initialized   bool
	lastAt        time.Time
	lastTotalUp   int64
	lastTotalDown int64
	conns         map[string]connByteCounter
	maxGap        time.Duration
}

func newTrafficSplitTracker(maxGap time.Duration) *trafficSplitTracker {
	if maxGap <= 0 {
		maxGap = 15 * time.Second
	}
	return &trafficSplitTracker{
		conns:  make(map[string]connByteCounter),
		maxGap: maxGap,
	}
}

func (t *trafficSplitTracker) Reset() {
	t.initialized = false
	t.lastAt = time.Time{}
	t.lastTotalUp = 0
	t.lastTotalDown = 0
	clear(t.conns)
}

// isDirectChain reports whether a Clash API connection outbound chain terminated on direct.
func isDirectChain(chains []string) bool {
	sawDirect := false
	for _, raw := range chains {
		tag := strings.TrimSpace(raw)
		if tag == "" {
			continue
		}
		if strings.EqualFold(tag, "direct") {
			sawDirect = true
			continue
		}
		lower := strings.ToLower(tag)
		if strings.HasPrefix(lower, "node-") ||
			strings.HasPrefix(lower, "xray-") ||
			strings.HasPrefix(lower, "tailscale") {
			return false
		}
	}
	return sawDirect
}

func reconcileSplitDelta(totalDelta, directDelta, proxyDelta int64, defaultDirect func() bool) (int64, int64) {
	if totalDelta < 0 {
		totalDelta = 0
	}
	if directDelta < 0 {
		directDelta = 0
	}
	if proxyDelta < 0 {
		proxyDelta = 0
	}
	tracked := directDelta + proxyDelta
	if totalDelta <= tracked {
		return directDelta, proxyDelta
	}
	rem := totalDelta - tracked
	if tracked > 0 {
		addDirect := int64(math.Round(float64(rem) * (float64(directDelta) / float64(tracked))))
		if addDirect > rem {
			addDirect = rem
		}
		directDelta += addDirect
		proxyDelta += rem - addDirect
		return directDelta, proxyDelta
	}
	if defaultDirect != nil && defaultDirect() {
		directDelta += rem
	} else {
		proxyDelta += rem
	}
	return directDelta, proxyDelta
}

// Update ingests a ConnectionsSnapshot and computes per-second split rates since the prior tick.
// On the first snapshot, after a stale gap (> maxGap), or after core counter reset, it seeds
// baseline counters and returns zero rates to prevent artificial throughput spikes.
func (t *trafficSplitTracker) Update(snap *clashapi.ConnectionsSnapshot, now time.Time, defaultDirect func() bool) TrafficRates {
	rates, _ := t.UpdateWithDeltas(snap, now, defaultDirect)
	return rates
}

func (t *trafficSplitTracker) UpdateWithDeltas(snap *clashapi.ConnectionsSnapshot, now time.Time, defaultDirect func() bool) (TrafficRates, trafficSplitDeltas) {
	out := TrafficRates{Timestamp: now.UnixMilli()}
	var deltas trafficSplitDeltas
	if snap == nil {
		return out, deltas
	}
	out.ActiveConnections = len(snap.Connections)

	nextConns := make(map[string]connByteCounter, len(snap.Connections))
	staleOrReset := !t.initialized ||
		now.Before(t.lastAt) ||
		now.Sub(t.lastAt) > t.maxGap ||
		snap.UploadTotal < t.lastTotalUp ||
		snap.DownloadTotal < t.lastTotalDown

	if staleOrReset {
		for _, c := range snap.Connections {
			if c.ID == "" {
				continue
			}
			nextConns[c.ID] = connByteCounter{
				up:     maxInt64(0, c.Upload),
				down:   maxInt64(0, c.Download),
				direct: isDirectChain(c.Chains),
			}
		}
		t.conns = nextConns
		t.lastTotalUp = maxInt64(0, snap.UploadTotal)
		t.lastTotalDown = maxInt64(0, snap.DownloadTotal)
		t.lastAt = now
		t.initialized = true
		return out, deltas
	}

	elapsed := now.Sub(t.lastAt).Seconds()
	if elapsed < 0.25 {
		elapsed = 1.0
	}

	totalUpDelta := maxInt64(0, snap.UploadTotal-t.lastTotalUp)
	totalDownDelta := maxInt64(0, snap.DownloadTotal-t.lastTotalDown)

	var directUpDelta, directDownDelta int64
	var proxyUpDelta, proxyDownDelta int64

	for _, c := range snap.Connections {
		if c.ID == "" {
			continue
		}
		curUp := maxInt64(0, c.Upload)
		curDown := maxInt64(0, c.Download)
		direct := isDirectChain(c.Chains)

		var du, dd int64
		if prev, ok := t.conns[c.ID]; ok {
			du = maxInt64(0, curUp-prev.up)
			dd = maxInt64(0, curDown-prev.down)
		} else {
			du = curUp
			dd = curDown
		}
		if direct {
			directUpDelta += du
			directDownDelta += dd
		} else {
			proxyUpDelta += du
			proxyDownDelta += dd
		}
		nextConns[c.ID] = connByteCounter{up: curUp, down: curDown, direct: direct}
	}

	directUpDelta, proxyUpDelta = reconcileSplitDelta(totalUpDelta, directUpDelta, proxyUpDelta, defaultDirect)
	directDownDelta, proxyDownDelta = reconcileSplitDelta(totalDownDelta, directDownDelta, proxyDownDelta, defaultDirect)

	deltas = trafficSplitDeltas{
		proxyUp:    proxyUpDelta,
		proxyDown:  proxyDownDelta,
		directUp:   directUpDelta,
		directDown: directDownDelta,
	}

	out.ProxyUp = int64(math.Round(float64(proxyUpDelta) / elapsed))
	out.ProxyDown = int64(math.Round(float64(proxyDownDelta) / elapsed))
	out.DirectUp = int64(math.Round(float64(directUpDelta) / elapsed))
	out.DirectDown = int64(math.Round(float64(directDownDelta) / elapsed))
	out.Up = out.ProxyUp + out.DirectUp
	out.Down = out.ProxyDown + out.DirectDown

	t.conns = nextConns
	t.lastTotalUp = maxInt64(0, snap.UploadTotal)
	t.lastTotalDown = maxInt64(0, snap.DownloadTotal)
	t.lastAt = now
	return out, deltas
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (s *Server) isDirectRoutingMode() bool {
	if mode := s.runtimeState().routingMode; mode != "" {
		return mode == "direct"
	}
	profile, err := s.routingProfile()
	if err != nil {
		return false
	}
	s.setCachedRoutingMode(profile.Mode)
	return strings.EqualFold(strings.TrimSpace(profile.Mode), "direct")
}

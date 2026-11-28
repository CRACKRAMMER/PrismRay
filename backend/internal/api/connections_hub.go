// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"sync"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/clashapi"
)

// connectionsHub multiplexes a single upstream Clash API /connections WebSocket stream
// across all /api/traffic subscribers, /api/connections subscribers, and Android screen-on
// telemetry callers, automatically tearing down upstream streaming when idle.
type connectionsHub struct {
	server *Server

	mu            sync.Mutex
	trafficSubs   map[chan TrafficRates]struct{}
	connSubs      map[chan clashapi.ConnectionsSnapshot]struct{}
	running       bool
	loopGen       uint64
	cancel        context.CancelFunc
	lastDemandAt  time.Time
	lastRates     TrafficRates
	lastSnap      clashapi.ConnectionsSnapshot
	lastSnapAt    time.Time
	lastSingBoxID int
	hasRates      bool

	deltaCbMu sync.RWMutex
	onDelta   func(proxyUp, proxyDown, directUp, directDown int64)
}

func newConnectionsHub(s *Server) *connectionsHub {
	return &connectionsHub{
		server:      s,
		trafficSubs: make(map[chan TrafficRates]struct{}),
		connSubs:    make(map[chan clashapi.ConnectionsSnapshot]struct{}),
	}
}

func (h *connectionsHub) SetDeltaObserver(fn func(proxyUp, proxyDown, directUp, directDown int64)) {
	h.deltaCbMu.Lock()
	h.onDelta = fn
	h.deltaCbMu.Unlock()
}

func (h *connectionsHub) SubscribeTraffic() (<-chan TrafficRates, func()) {
	ch := make(chan TrafficRates, 4)
	h.mu.Lock()
	h.trafficSubs[ch] = struct{}{}
	h.lastDemandAt = time.Now()
	if h.hasRates && time.Since(h.lastSnapAt) < 4*time.Second {
		select {
		case ch <- h.lastRates:
		default:
		}
	}
	h.ensureLoopLocked()
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.trafficSubs, ch)
		h.mu.Unlock()
	}
}

func (h *connectionsHub) SubscribeConnections() (<-chan clashapi.ConnectionsSnapshot, func()) {
	ch := make(chan clashapi.ConnectionsSnapshot, 4)
	h.mu.Lock()
	h.connSubs[ch] = struct{}{}
	h.lastDemandAt = time.Now()
	if !h.lastSnapAt.IsZero() && time.Since(h.lastSnapAt) < 4*time.Second {
		snap := h.lastSnap
		if snap.Connections == nil {
			snap.Connections = []clashapi.ConnectionItem{}
		}
		select {
		case ch <- snap:
		default:
		}
	}
	h.ensureLoopLocked()
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.connSubs, ch)
		h.mu.Unlock()
	}
}

// TelemetryRates returns the freshest split traffic rates and cumulative byte totals for
// screen-on Android notifications, reusing the shared hub stream whenever active.
func (h *connectionsHub) TelemetryRates(ctx context.Context, singBoxPID int) (rates TrafficRates, uploadTotal, downloadTotal int64, ok bool) {
	now := time.Now()
	h.mu.Lock()
	h.lastDemandAt = now
	h.ensureLoopLocked()
	if h.hasRates && h.lastSingBoxID == singBoxPID && now.Sub(h.lastSnapAt) <= 4*time.Second {
		rates = h.lastRates
		uploadTotal = h.lastSnap.UploadTotal
		downloadTotal = h.lastSnap.DownloadTotal
		h.mu.Unlock()
		return rates, uploadTotal, downloadTotal, true
	}
	h.mu.Unlock()

	// Cold start on first screen-on poll before the background WS delivers frame 1.
	client := h.server.ensureOrchestrator().ClashClient()
	if client == nil {
		return TrafficRates{Timestamp: now.UnixMilli()}, 0, 0, false
	}
	snap, err := client.GetConnections(ctx)
	if err != nil || snap == nil {
		return TrafficRates{Timestamp: now.UnixMilli()}, 0, 0, false
	}
	h.server.androidTrafficMu.Lock()
	if h.server.androidTrafficTracker == nil {
		h.server.androidTrafficTracker = newTrafficSplitTracker(15 * time.Second)
	}
	if h.server.androidTrafficPID != singBoxPID {
		h.server.androidTrafficTracker.Reset()
		h.server.androidTrafficPID = singBoxPID
	}
	rates = h.server.androidTrafficTracker.Update(snap, time.Now(), h.server.isDirectRoutingMode)
	h.server.androidTrafficMu.Unlock()
	return rates, snap.UploadTotal, snap.DownloadTotal, true
}

func (h *connectionsHub) Stop() {
	h.mu.Lock()
	cancel := h.cancel
	h.loopGen++
	h.running = false
	h.cancel = nil
	h.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (h *connectionsHub) ensureLoopLocked() {
	if h.running {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.loopGen++
	gen := h.loopGen
	h.running = true
	h.cancel = cancel
	go h.runLoop(ctx, gen)
}

func (h *connectionsHub) hasDemandLocked(now time.Time) bool {
	if len(h.trafficSubs) > 0 || len(h.connSubs) > 0 {
		return true
	}
	return !h.lastDemandAt.IsZero() && now.Sub(h.lastDemandAt) < 8*time.Second
}

func (h *connectionsHub) broadcast(rates TrafficRates, snap clashapi.ConnectionsSnapshot, pid int) {
	if snap.Connections == nil {
		snap.Connections = []clashapi.ConnectionItem{}
	}
	now := time.Now()
	h.mu.Lock()
	h.lastRates = rates
	h.lastSnap = snap
	h.lastSnapAt = now
	h.lastSingBoxID = pid
	h.hasRates = true
	for ch := range h.trafficSubs {
		select {
		case ch <- rates:
		default:
			// Drop stale unread sample so slow clients never stall the hub.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- rates:
			default:
			}
		}
	}
	for ch := range h.connSubs {
		select {
		case ch <- snap:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- snap:
			default:
			}
		}
	}
	h.mu.Unlock()
}

func (h *connectionsHub) runLoop(ctx context.Context, gen uint64) {
	defer func() {
		h.mu.Lock()
		if h.loopGen == gen {
			h.running = false
			h.cancel = nil
			// If a new subscriber arrived right as this loop exited, immediately respawn so it is never stranded.
			if h.hasDemandLocked(time.Now()) {
				h.ensureLoopLocked()
			}
		}
		h.mu.Unlock()
	}()

	tracker := newTrafficSplitTracker(15 * time.Second)
	orch := h.server.ensureOrchestrator()
	idleCheck := time.NewTicker(2 * time.Second)
	defer idleCheck.Stop()

	for {
		h.mu.Lock()
		demand := h.hasDemandLocked(time.Now())
		if !demand {
			h.running = false
			h.cancel = nil
			h.mu.Unlock()
			return
		}
		h.mu.Unlock()

		client := orch.ClashClient()
		st := orch.Status()
		if client != nil && st.Running {
			streamCtx, streamCancel := context.WithCancel(ctx)
			ch, errCh := client.StreamConnections(streamCtx, 1000)
			closed := false
			for !closed {
				select {
				case <-ctx.Done():
					streamCancel()
					return
				case snap, ok := <-ch:
					if !ok {
						closed = true
						break
					}
					rates, deltas := tracker.UpdateWithDeltas(&snap, time.Now(), h.server.isDirectRoutingMode)
					h.broadcast(rates, snap, st.SingBoxPID)
					if deltas.proxyUp > 0 || deltas.proxyDown > 0 || deltas.directUp > 0 || deltas.directDown > 0 {
						h.deltaCbMu.RLock()
						cb := h.onDelta
						h.deltaCbMu.RUnlock()
						if cb != nil {
							cb(deltas.proxyUp, deltas.proxyDown, deltas.directUp, deltas.directDown)
						}
					}
				case <-errCh:
					closed = true
				case <-idleCheck.C:
					h.mu.Lock()
					stillNeeded := h.hasDemandLocked(time.Now())
					if !stillNeeded && h.loopGen == gen {
						h.running = false
						h.cancel = nil
					}
					h.mu.Unlock()
					if !stillNeeded {
						streamCancel()
						return
					}
				}
			}
			streamCancel()
		}

		tracker.Reset()
		zeroRates := TrafficRates{Timestamp: time.Now().UnixMilli()}
		emptySnap := clashapi.ConnectionsSnapshot{Connections: []clashapi.ConnectionItem{}}
		h.broadcast(zeroRates, emptySnap, 0)

		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Second):
		}
	}
}

func (s *Server) ensureConnectionsHub() *connectionsHub {
	s.connHubMu.Lock()
	defer s.connHubMu.Unlock()
	if s.connHub == nil {
		s.connHub = newConnectionsHub(s)
		ledger := s.ensureTrafficLedger()
		s.connHub.SetDeltaObserver(ledger.Record)
	}
	return s.connHub
}

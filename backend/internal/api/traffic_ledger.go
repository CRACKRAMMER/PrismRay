// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

type trafficBucketTotals struct {
	ProxyUp    int64 `json:"proxy_up"`
	ProxyDown  int64 `json:"proxy_down"`
	DirectUp   int64 `json:"direct_up"`
	DirectDown int64 `json:"direct_down"`
}

type trafficLedger struct {
	store *storage.Store

	mu            sync.Mutex
	pendingHourly map[int64]trafficBucketTotals
	pendingDaily  map[int64]trafficBucketTotals
	lastFlush     time.Time
	lastPrune     time.Time
}

func newTrafficLedger(store *storage.Store) *trafficLedger {
	now := time.Now().UTC()
	return &trafficLedger{
		store:         store,
		pendingHourly: make(map[int64]trafficBucketTotals),
		pendingDaily:  make(map[int64]trafficBucketTotals),
		lastFlush:     now,
	}
}

func utcHourBucket(t time.Time) int64 {
	return t.UTC().Truncate(time.Hour).Unix()
}

func utcDayBucket(t time.Time) int64 {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).Unix()
}

// Record accumulates a split traffic byte delta in memory for batched persistence.
func (l *trafficLedger) Record(proxyUp, proxyDown, directUp, directDown int64) {
	l.RecordAt(time.Now().UTC(), proxyUp, proxyDown, directUp, directDown)
}

func (l *trafficLedger) RecordAt(at time.Time, proxyUp, proxyDown, directUp, directDown int64) {
	if proxyUp <= 0 && proxyDown <= 0 && directUp <= 0 && directDown <= 0 {
		return
	}
	if proxyUp < 0 {
		proxyUp = 0
	}
	if proxyDown < 0 {
		proxyDown = 0
	}
	if directUp < 0 {
		directUp = 0
	}
	if directDown < 0 {
		directDown = 0
	}
	hourKey := utcHourBucket(at)
	dayKey := utcDayBucket(at)

	l.mu.Lock()
	h := l.pendingHourly[hourKey]
	h.ProxyUp += proxyUp
	h.ProxyDown += proxyDown
	h.DirectUp += directUp
	h.DirectDown += directDown
	l.pendingHourly[hourKey] = h

	d := l.pendingDaily[dayKey]
	d.ProxyUp += proxyUp
	d.ProxyDown += proxyDown
	d.DirectUp += directUp
	d.DirectDown += directDown
	l.pendingDaily[dayKey] = d
	l.mu.Unlock()
}

// MaybeFlush flushes pending in-memory deltas once every 60 seconds and prunes expired buckets hourly.
func (l *trafficLedger) MaybeFlush() {
	l.mu.Lock()
	due := time.Since(l.lastFlush) >= 60*time.Second && (len(l.pendingHourly) > 0 || len(l.pendingDaily) > 0)
	l.mu.Unlock()
	if due {
		_ = l.Flush()
	}
}

// Flush persists all pending in-memory deltas into SQLite and prunes expired records when due.
func (l *trafficLedger) Flush() error {
	if l == nil || l.store == nil {
		return nil
	}
	l.mu.Lock()
	if len(l.pendingHourly) == 0 && len(l.pendingDaily) == 0 {
		l.lastFlush = time.Now().UTC()
		l.mu.Unlock()
		return nil
	}
	hourly := l.pendingHourly
	daily := l.pendingDaily
	l.pendingHourly = make(map[int64]trafficBucketTotals)
	l.pendingDaily = make(map[int64]trafficBucketTotals)
	l.lastFlush = time.Now().UTC()
	shouldPrune := l.lastPrune.IsZero() || time.Since(l.lastPrune) >= time.Hour
	if shouldPrune {
		l.lastPrune = l.lastFlush
	}
	l.mu.Unlock()

	batch := make([]storage.TrafficBucket, 0, len(hourly)+len(daily))
	for ts, v := range hourly {
		batch = append(batch, storage.TrafficBucket{
			BucketUnix:  ts,
			Granularity: "hour",
			ProxyUp:     v.ProxyUp,
			ProxyDown:   v.ProxyDown,
			DirectUp:    v.DirectUp,
			DirectDown:  v.DirectDown,
		})
	}
	for ts, v := range daily {
		batch = append(batch, storage.TrafficBucket{
			BucketUnix:  ts,
			Granularity: "day",
			ProxyUp:     v.ProxyUp,
			ProxyDown:   v.ProxyDown,
			DirectUp:    v.DirectUp,
			DirectDown:  v.DirectDown,
		})
	}
	if err := l.store.AddTrafficBucketDeltas(batch); err != nil {
		// Re-queue failed deltas so data is not lost on transient busy errors.
		l.mu.Lock()
		for ts, v := range hourly {
			cur := l.pendingHourly[ts]
			cur.ProxyUp += v.ProxyUp
			cur.ProxyDown += v.ProxyDown
			cur.DirectUp += v.DirectUp
			cur.DirectDown += v.DirectDown
			l.pendingHourly[ts] = cur
		}
		for ts, v := range daily {
			cur := l.pendingDaily[ts]
			cur.ProxyUp += v.ProxyUp
			cur.ProxyDown += v.ProxyDown
			cur.DirectUp += v.DirectUp
			cur.DirectDown += v.DirectDown
			l.pendingDaily[ts] = cur
		}
		l.mu.Unlock()
		return err
	}

	if shouldPrune {
		now := time.Now().UTC()
		_ = l.store.PruneTrafficBuckets("hour", utcHourBucket(now.Add(-48*time.Hour)))
		_ = l.store.PruneTrafficBuckets("day", utcDayBucket(now.AddDate(0, 0, -90)))
	}
	return nil
}

// Clear resets both pending in-memory counters and SQLite traffic history.
func (l *trafficLedger) Clear() error {
	l.mu.Lock()
	l.pendingHourly = make(map[int64]trafficBucketTotals)
	l.pendingDaily = make(map[int64]trafficBucketTotals)
	l.mu.Unlock()
	if l.store == nil {
		return nil
	}
	return l.store.ClearTrafficBuckets()
}

type TrafficHistoryResponse struct {
	Range       string                  `json:"range"`
	Granularity string                  `json:"granularity"`
	Totals      trafficBucketTotals     `json:"totals"`
	Buckets     []storage.TrafficBucket `json:"buckets"`
}

func (l *trafficLedger) Query(rangeKey string, now time.Time) (TrafficHistoryResponse, error) {
	now = now.UTC()
	granularity := "hour"
	var count int
	var startUnix int64
	var step int64

	switch strings.ToLower(strings.TrimSpace(rangeKey)) {
	case "7d":
		rangeKey = "7d"
		granularity = "day"
		count = 7
		step = 86400
		startUnix = utcDayBucket(now.AddDate(0, 0, -(count - 1)))
	case "30d":
		rangeKey = "30d"
		granularity = "day"
		count = 30
		step = 86400
		startUnix = utcDayBucket(now.AddDate(0, 0, -(count - 1)))
	default:
		rangeKey = "24h"
		granularity = "hour"
		count = 24
		step = 3600
		startUnix = utcHourBucket(now.Add(-time.Duration(count-1) * time.Hour))
	}

	byTS := make(map[int64]trafficBucketTotals, count)
	if l != nil && l.store != nil {
		stored, err := l.store.ListTrafficBuckets(granularity, startUnix)
		if err != nil {
			return TrafficHistoryResponse{}, err
		}
		for _, b := range stored {
			cur := byTS[b.BucketUnix]
			cur.ProxyUp += b.ProxyUp
			cur.ProxyDown += b.ProxyDown
			cur.DirectUp += b.DirectUp
			cur.DirectDown += b.DirectDown
			byTS[b.BucketUnix] = cur
		}
	}

	// Overlay unflushed in-memory deltas for instant feedback.
	if l != nil {
		l.mu.Lock()
		src := l.pendingHourly
		if granularity == "day" {
			src = l.pendingDaily
		}
		for ts, v := range src {
			if ts < startUnix {
				continue
			}
			cur := byTS[ts]
			cur.ProxyUp += v.ProxyUp
			cur.ProxyDown += v.ProxyDown
			cur.DirectUp += v.DirectUp
			cur.DirectDown += v.DirectDown
			byTS[ts] = cur
		}
		l.mu.Unlock()
	}

	buckets := make([]storage.TrafficBucket, 0, count)
	var totals trafficBucketTotals
	for i := 0; i < count; i++ {
		ts := startUnix + int64(i)*step
		v := byTS[ts]
		totals.ProxyUp += v.ProxyUp
		totals.ProxyDown += v.ProxyDown
		totals.DirectUp += v.DirectUp
		totals.DirectDown += v.DirectDown
		buckets = append(buckets, storage.TrafficBucket{
			BucketUnix:  ts,
			Granularity: granularity,
			ProxyUp:     v.ProxyUp,
			ProxyDown:   v.ProxyDown,
			DirectUp:    v.DirectUp,
			DirectDown:  v.DirectDown,
		})
	}
	return TrafficHistoryResponse{
		Range:       rangeKey,
		Granularity: granularity,
		Totals:      totals,
		Buckets:     buckets,
	}, nil
}

func (s *Server) ensureTrafficLedger() *trafficLedger {
	s.ledgerMu.Lock()
	defer s.ledgerMu.Unlock()
	if s.trafficLedger == nil {
		s.trafficLedger = newTrafficLedger(s.store)
	}
	return s.trafficLedger
}

func (s *Server) handleTrafficHistory(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rangeKey := r.URL.Query().Get("range")
		resp, err := s.ensureTrafficLedger().Query(rangeKey, time.Now().UTC())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodDelete:
		if err := s.ensureTrafficLedger().Clear(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

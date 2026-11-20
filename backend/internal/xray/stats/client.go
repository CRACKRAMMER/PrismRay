// SPDX-License-Identifier: MPL-2.0

package stats

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TrafficSnapshot contains current traffic speeds.
type TrafficSnapshot struct {
	DownlinkBytes int64   `json:"downlink_bytes"` // bytes since last reset
	UplinkBytes   int64   `json:"uplink_bytes"`
	DownloadSpeed float64 `json:"download_speed"` // MB/s
	UploadSpeed   float64 `json:"upload_speed"`   // MB/s
	Timestamp     int64   `json:"timestamp"`
}

// Client queries Xray stats API via the xray binary CLI.
type Client struct {
	mu          sync.RWMutex
	xrayPath    string
	apiAddr     string // e.g. "127.0.0.1:10085"
	interval    time.Duration
	cancel      context.CancelFunc
	done        chan struct{}
	lifecycleMu sync.Mutex
	running     bool
	latest      *TrafficSnapshot
	subscribers []chan *TrafficSnapshot
	subMu       sync.Mutex
}

// NewClient creates a new stats client.
func NewClient(xrayPath string, apiAddr string) *Client {
	return &Client{
		xrayPath: xrayPath,
		apiAddr:  apiAddr,
		interval: time.Second,
	}
}

// SetXrayPath updates the path to the xray binary.
func (c *Client) SetXrayPath(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.xrayPath = path
}

// Subscribe returns a channel that receives traffic snapshots.
func (c *Client) Subscribe() chan *TrafficSnapshot {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	ch := make(chan *TrafficSnapshot, 10)
	c.subscribers = append(c.subscribers, ch)
	return ch
}

// Unsubscribe removes a subscriber channel.
func (c *Client) Unsubscribe(ch chan *TrafficSnapshot) {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	for i, sub := range c.subscribers {
		if sub == ch {
			c.subscribers = append(c.subscribers[:i], c.subscribers[i+1:]...)
			close(ch)
			return
		}
	}
}

// Start begins periodic stats polling.
func (c *Client) Start() {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.running {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.done = make(chan struct{})
	c.running = true
	go func() { defer close(c.done); c.pollLoop(ctx) }()
}

func (c *Client) Stop() {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if !c.running {
		return
	}
	c.cancel()
	<-c.done
	c.running = false
}

// Latest returns the most recent traffic snapshot.
func (c *Client) Latest() *TrafficSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest
}

func (c *Client) pollLoop(ctx context.Context) {
	last := time.Now()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := c.queryStats(ctx)
			now := time.Now()
			elapsed := now.Sub(last).Seconds()
			last = now
			snap.DownloadSpeed = float64(snap.DownlinkBytes) / 1024 / 1024 / elapsed
			snap.UploadSpeed = float64(snap.UplinkBytes) / 1024 / 1024 / elapsed
			c.mu.Lock()
			c.latest = snap
			c.mu.Unlock()

			// Broadcast to subscribers
			c.subMu.Lock()
			for _, sub := range c.subscribers {
				select {
				case sub <- snap:
				default:
					// drop if subscriber can't keep up
				}
			}
			c.subMu.Unlock()
		}
	}
}

// statLine matches lines like: name: "outbound>>>proxy>>>traffic>>>downlink"  value: 12345
var reStatName = regexp.MustCompile(`name:\s*"([^"]+)"`)
var reStatValue = regexp.MustCompile(`value:\s*(\d+)`)

func (c *Client) queryStats(parent context.Context) *TrafficSnapshot {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	c.mu.RLock()
	xrayPath := c.xrayPath
	apiAddr := c.apiAddr
	c.mu.RUnlock()

	if xrayPath == "" {
		return &TrafficSnapshot{Timestamp: time.Now().UnixMilli()}
	}

	// Query with -reset so we get delta since last read
	cmd := exec.CommandContext(ctx, xrayPath, "api", "statsquery",
		fmt.Sprintf("--server=%s", apiAddr),
		"-reset",
	)
	output, err := cmd.Output()
	if err != nil {
		return &TrafficSnapshot{Timestamp: time.Now().UnixMilli()}
	}

	snap := &TrafficSnapshot{Timestamp: time.Now().UnixMilli()}
	parseStatsOutput(string(output), snap)

	return snap
}

func parseStatsOutput(output string, snap *TrafficSnapshot) {
	// Recent CLI versions emit JSON; retain text-protobuf compatibility.
	var response struct {
		Stat []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	if json.Unmarshal([]byte(output), &response) == nil {
		for _, stat := range response.Stat {
			value, _ := strconv.ParseInt(strings.Trim(string(stat.Value), "\""), 10, 64)
			addCounter(stat.Name, value, snap)
		}
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(output))
	var currentName string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := reStatName.FindStringSubmatch(line); len(matches) > 1 {
			currentName = matches[1]
		}
		if matches := reStatValue.FindStringSubmatch(line); len(matches) > 1 {
			val, _ := strconv.ParseInt(matches[1], 10, 64)
			addCounter(currentName, val, snap)
		}
	}
}

// Count one side of the proxy only; inbound and outbound count the same bytes.
func addCounter(name string, value int64, snap *TrafficSnapshot) {
	if !strings.HasPrefix(name, "outbound>>>") {
		return
	}
	if strings.HasSuffix(name, ">>>traffic>>>downlink") {
		snap.DownlinkBytes += value
	}
	if strings.HasSuffix(name, ">>>traffic>>>uplink") {
		snap.UplinkBytes += value
	}
}

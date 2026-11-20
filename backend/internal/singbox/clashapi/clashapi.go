// SPDX-License-Identifier: MPL-2.0

package clashapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Client communicates with sing-box's experimental Clash REST and WebSocket API.
type Client struct {
	baseURL    string
	wsBaseURL  string
	secret     string
	httpClient *http.Client
}

// DelayHistory records an individual probe delay sample reported by Clash API.
type DelayHistory struct {
	Time  string `json:"time"`
	Delay int    `json:"delay"`
}

// ProxyInfo describes a proxy outbound, endpoint, or selector group.
type ProxyInfo struct {
	Name    string         `json:"name"`
	Type    string         `json:"type"`
	Now     string         `json:"now,omitempty"`
	All     []string       `json:"all,omitempty"`
	UDP     bool           `json:"udp,omitempty"`
	History []DelayHistory `json:"history,omitempty"`
}

// ProxiesResponse is returned by GET /proxies.
type ProxiesResponse struct {
	Proxies map[string]ProxyInfo `json:"proxies"`
}

// ConnectionMetadata describes source/destination properties for a tracked connection.
type ConnectionMetadata struct {
	Network           string `json:"network"`
	Type              string `json:"type"`
	SourceIP          string `json:"sourceIP"`
	DestinationIP     string `json:"destinationIP"`
	SourcePort        string `json:"sourcePort"`
	DestinationPort   string `json:"destinationPort"`
	Host              string `json:"host"`
	DNSMode           string `json:"dnsMode,omitempty"`
	ProcessPath       string `json:"processPath,omitempty"`
	SpecialProxy      string `json:"specialProxy,omitempty"`
	RemoteDestination string `json:"remoteDestination,omitempty"`
}

// ConnectionItem describes a single active connection in Clash API snapshots.
type ConnectionItem struct {
	ID          string             `json:"id"`
	Metadata    ConnectionMetadata `json:"metadata"`
	Upload      int64              `json:"upload"`
	Download    int64              `json:"download"`
	Start       string             `json:"start"`
	Chains      []string           `json:"chains"`
	Rule        string             `json:"rule"`
	RulePayload string             `json:"rulePayload,omitempty"`
}

// ConnectionsSnapshot represents the response of GET /connections and WS /connections.
type ConnectionsSnapshot struct {
	DownloadTotal int64            `json:"downloadTotal"`
	UploadTotal   int64            `json:"uploadTotal"`
	Memory        int64            `json:"memory,omitempty"`
	Connections   []ConnectionItem `json:"connections"`
}

// TrafficFrame represents a per-second bandwidth sample from WS /traffic.
type TrafficFrame struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// New constructs a Client from an address ("127.0.0.1:9090") or HTTP URL.
func New(addrOrURL, secret string) *Client {
	base := strings.TrimSpace(addrOrURL)
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	base = strings.TrimRight(base, "/")

	wsBase := strings.Replace(base, "https://", "wss://", 1)
	wsBase = strings.Replace(wsBase, "http://", "ws://", 1)

	return &Client{
		baseURL:   base,
		wsBaseURL: wsBase,
		secret:    secret,
		httpClient: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{Proxy: nil},
		},
	}
}

// BaseURL returns the normalized HTTP base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// GetProxies returns all configured proxies and selector groups.
func (c *Client) GetProxies(ctx context.Context) (*ProxiesResponse, error) {
	var out ProxiesResponse
	if err := c.doJSON(ctx, http.MethodGet, "/proxies", nil, &out); err != nil {
		return nil, err
	}
	if out.Proxies == nil {
		out.Proxies = map[string]ProxyInfo{}
	}
	return &out, nil
}

// SelectProxy hot-switches an active selector group without restarting sing-box.
func (c *Client) SelectProxy(ctx context.Context, groupTag, targetTag string) error {
	path := "/proxies/" + url.PathEscape(groupTag)
	payload := map[string]string{"name": targetTag}
	return c.doJSON(ctx, http.MethodPut, path, payload, nil)
}

// ProbeDelay triggers a live URL delay test for a loaded outbound/group tag.
func (c *Client) ProbeDelay(ctx context.Context, tag, testURL string, timeoutMS int) (int, error) {
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	if timeoutMS <= 0 {
		timeoutMS = 5000
	}
	q := url.Values{}
	q.Set("timeout", fmt.Sprintf("%d", timeoutMS))
	q.Set("url", testURL)
	path := "/proxies/" + url.PathEscape(tag) + "/delay?" + q.Encode()

	// Give the HTTP client slightly more room than the probe timeout itself.
	probeCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMS+2000)*time.Millisecond)
		defer cancel()
	}

	var resp struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	if err := c.doJSON(probeCtx, http.MethodGet, path, nil, &resp); err != nil {
		return 0, err
	}
	if resp.Delay <= 0 && resp.Message != "" {
		return 0, fmt.Errorf("clashapi delay failed: %s", resp.Message)
	}
	return resp.Delay, nil
}

// GetConnections fetches the current active connections snapshot.
func (c *Client) GetConnections(ctx context.Context) (*ConnectionsSnapshot, error) {
	var out ConnectionsSnapshot
	if err := c.doJSON(ctx, http.MethodGet, "/connections", nil, &out); err != nil {
		return nil, err
	}
	if out.Connections == nil {
		out.Connections = []ConnectionItem{}
	}
	return &out, nil
}

// CloseConnection closes a single active connection by ID.
func (c *Client) CloseConnection(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
}

// CloseAllConnections closes all currently active connections.
func (c *Client) CloseAllConnections(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodDelete, "/connections", nil, nil)
}

// SetMode updates the Clash routing mode ("Rule", "Global", or "Direct").
func (c *Client) SetMode(ctx context.Context, mode string) error {
	return c.doJSON(ctx, http.MethodPatch, "/configs", map[string]string{"mode": mode}, nil)
}

// StreamTraffic opens a WebSocket connection to /traffic and streams rate samples.
func (c *Client) StreamTraffic(ctx context.Context) (<-chan TrafficFrame, <-chan error) {
	frames := make(chan TrafficFrame, 16)
	errs := make(chan error, 1)

	go func() {
		defer close(frames)
		defer close(errs)

		conn, err := c.dialWS(ctx, "/traffic")
		if err != nil {
			select {
			case errs <- err:
			default:
			}
			return
		}
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.Close()
			case <-done:
			}
		}()
		defer conn.Close()

		for {
			var frame TrafficFrame
			if err := conn.ReadJSON(&frame); err != nil {
				if ctx.Err() == nil {
					select {
					case errs <- err:
					default:
					}
				}
				return
			}
			select {
			case frames <- frame:
			case <-ctx.Done():
				return
			}
		}
	}()

	return frames, errs
}

// StreamConnections opens a WebSocket connection to /connections and streams snapshots.
func (c *Client) StreamConnections(ctx context.Context, intervalMS int) (<-chan ConnectionsSnapshot, <-chan error) {
	snaps := make(chan ConnectionsSnapshot, 8)
	errs := make(chan error, 1)
	if intervalMS <= 0 {
		intervalMS = 1000
	}

	go func() {
		defer close(snaps)
		defer close(errs)

		path := fmt.Sprintf("/connections?interval=%d", intervalMS)
		conn, err := c.dialWS(ctx, path)
		if err != nil {
			select {
			case errs <- err:
			default:
			}
			return
		}
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.Close()
			case <-done:
			}
		}()
		defer conn.Close()

		for {
			var snap ConnectionsSnapshot
			if err := conn.ReadJSON(&snap); err != nil {
				if ctx.Err() == nil {
					select {
					case errs <- err:
					default:
					}
				}
				return
			}
			if snap.Connections == nil {
				snap.Connections = []ConnectionItem{}
			}
			select {
			case snaps <- snap:
			case <-ctx.Done():
				return
			}
		}
	}()

	return snaps, errs
}

func (c *Client) dialWS(ctx context.Context, path string) (*websocket.Conn, error) {
	wsURL := c.wsBaseURL + path
	headers := http.Header{}
	if c.secret != "" {
		headers.Set("Authorization", "Bearer "+c.secret)
		sep := "?"
		if strings.Contains(wsURL, "?") {
			sep = "&"
		}
		wsURL += sep + "token=" + url.QueryEscape(c.secret)
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
		Proxy:            nil,
	}
	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return nil, fmt.Errorf("clashapi ws %s: %w", path, err)
	}
	return conn, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqBody any, out any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("clashapi %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("clashapi %s %s read: %w", method, path, err)
	}
	if resp.StatusCode >= 400 {
		var errPayload struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &errPayload)
		if errPayload.Message != "" {
			return fmt.Errorf("clashapi %s %s (%d): %s", method, path, resp.StatusCode, errPayload.Message)
		}
		return fmt.Errorf("clashapi %s %s returned HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("clashapi %s %s decode: %w", method, path, err)
		}
	}
	return nil
}

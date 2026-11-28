// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type taildropFileSnapshot struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	SenderName string `json:"sender_name,omitempty"`
	ModifiedAt int64  `json:"modified_at,omitempty"`
}

type taildropInboxSnapshot struct {
	CanShareFiles bool                   `json:"can_share_files"`
	Files         []taildropFileSnapshot `json:"files"`
	Receiving     int                    `json:"receiving"`
}

type tailscalePingSample struct {
	LatencyMs      float64 `json:"latency_ms"`
	IsDirect       bool    `json:"is_direct"`
	Endpoint       string  `json:"endpoint,omitempty"`
	PeerRelay      string  `json:"peer_relay,omitempty"`
	DERPRegionID   int32   `json:"derp_region_id,omitempty"`
	DERPRegionCode string  `json:"derp_region_code,omitempty"`
	Error          string  `json:"error,omitempty"`
}

type tailscalePingResponse struct {
	PeerIP         string                `json:"peer_ip"`
	LatencyMs      float64               `json:"latency_ms"`
	MinMs          float64               `json:"min_ms"`
	AvgMs          float64               `json:"avg_ms"`
	IsDirect       bool                  `json:"is_direct"`
	Endpoint       string                `json:"endpoint,omitempty"`
	PeerRelay      string                `json:"peer_relay,omitempty"`
	DERPRegionID   int32                 `json:"derp_region_id,omitempty"`
	DERPRegionCode string                `json:"derp_region_code,omitempty"`
	Samples        []tailscalePingSample `json:"samples"`
	Error          string                `json:"error,omitempty"`
}

type coreControlServer struct {
	token string
	tsEp  adapter.TailscaleEndpoint
	srv   *http.Server
	ln    net.Listener

	mu         sync.RWMutex
	lastStatus *tailscaleStatusSnapshot
	lastInbox  taildropInboxSnapshot
}

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

func sanitizeTaildropFileName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("invalid file name")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("invalid file name")
	}
	if filepath.Base(name) != name {
		return "", fmt.Errorf("invalid file name")
	}
	return name, nil
}

func newCoreControlServer(addr, token string, tsEp adapter.TailscaleEndpoint) (*coreControlServer, error) {
	addr = strings.TrimSpace(addr)
	token = strings.TrimSpace(token)
	if addr == "" || token == "" {
		return nil, nil
	}
	if !isLoopbackListenAddr(addr) {
		return nil, fmt.Errorf("core control address %q must bind loopback", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	cs := &coreControlServer{
		token:     token,
		tsEp:      tsEp,
		ln:        ln,
		lastInbox: taildropInboxSnapshot{Files: []taildropFileSnapshot{}},
	}
	cs.srv = &http.Server{
		Handler:           cs.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = cs.srv.Serve(ln)
	}()
	return cs, nil
}

func (c *coreControlServer) Addr() string {
	if c == nil || c.ln == nil {
		return ""
	}
	return c.ln.Addr().String()
}

func (c *coreControlServer) UpdateStatus(snap tailscaleStatusSnapshot) {
	if c == nil {
		return
	}
	snap.ControlAvailable = true
	c.mu.Lock()
	copySnap := snap
	c.lastStatus = &copySnap
	c.lastInbox.CanShareFiles = snap.CanShareFiles
	c.mu.Unlock()
}

func (c *coreControlServer) UpdateInbox(inbox *adapter.TaildropInbox) {
	if c == nil || inbox == nil {
		return
	}
	files := make([]taildropFileSnapshot, 0, len(inbox.Files))
	for _, f := range inbox.Files {
		if f == nil {
			continue
		}
		files = append(files, taildropFileSnapshot{
			Name:       f.Name,
			Size:       f.Size,
			SenderName: f.SenderName,
			ModifiedAt: f.ModifiedAt,
		})
	}
	c.mu.Lock()
	c.lastInbox.Files = files
	c.lastInbox.Receiving = len(inbox.Receiving)
	c.mu.Unlock()
}

func (c *coreControlServer) Close() {
	if c == nil || c.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.srv.Shutdown(ctx)
}

func (c *coreControlServer) authorized(r *http.Request) bool {
	got := strings.TrimSpace(r.Header.Get("Authorization"))
	want := "Bearer " + c.token
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (c *coreControlServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tailscale/status", c.handleStatus)
	mux.HandleFunc("POST /tailscale/exit-node", c.handleExitNode)
	mux.HandleFunc("POST /tailscale/ping", c.handlePing)
	mux.HandleFunc("POST /tailscale/logout", c.handleLogout)
	mux.HandleFunc("GET /tailscale/taildrop/inbox", c.handleTaildropInbox)
	mux.HandleFunc("POST /tailscale/taildrop/send", c.handleTaildropSend)
	mux.HandleFunc("GET /tailscale/taildrop/file/{name}", c.handleTaildropFile)
	mux.HandleFunc("DELETE /tailscale/taildrop/file/{name}", c.handleTaildropFile)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeCtrlJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (c *coreControlServer) handleStatus(w http.ResponseWriter, _ *http.Request) {
	c.mu.RLock()
	snap := c.lastStatus
	c.mu.RUnlock()
	if snap == nil {
		writeCtrlJSON(w, http.StatusOK, tailscaleStatusSnapshot{
			PID:              os.Getpid(),
			BackendState:     "Starting",
			ControlAvailable: true,
			UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
		})
		return
	}
	writeCtrlJSON(w, http.StatusOK, snap)
}

func (c *coreControlServer) handleExitNode(w http.ResponseWriter, r *http.Request) {
	if c.tsEp == nil {
		http.Error(w, "tailscale endpoint inactive", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		StableID string `json:"stable_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := c.tsEp.SetTailscaleExitNode(ctx, strings.TrimSpace(req.StableID)); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeCtrlJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"stable_id": strings.TrimSpace(req.StableID),
	})
}

func (c *coreControlServer) handlePing(w http.ResponseWriter, r *http.Request) {
	if c.tsEp == nil {
		http.Error(w, "tailscale endpoint inactive", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		PeerIP string `json:"peer_ip"`
		Count  int    `json:"count"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	peerIP := strings.TrimSpace(req.PeerIP)
	if _, err := netip.ParseAddr(peerIP); err != nil {
		http.Error(w, "valid tailscale peer_ip is required", http.StatusBadRequest)
		return
	}
	count := req.Count
	if count <= 0 {
		count = 3
	}
	if count > 5 {
		count = 5
	}

	pingCtx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	var mu sync.Mutex
	samples := make([]tailscalePingSample, 0, count)
	_ = c.tsEp.StartTailscalePing(pingCtx, peerIP, func(res *adapter.TailscalePingResult) {
		if res == nil {
			return
		}
		mu.Lock()
		samples = append(samples, tailscalePingSample{
			LatencyMs:      res.LatencyMs,
			IsDirect:       res.IsDirect,
			Endpoint:       res.Endpoint,
			PeerRelay:      res.PeerRelay,
			DERPRegionID:   res.DERPRegionID,
			DERPRegionCode: res.DERPRegionCode,
			Error:          res.Error,
		})
		done := len(samples) >= count
		mu.Unlock()
		if done {
			cancel()
		}
	})

	mu.Lock()
	collected := append([]tailscalePingSample(nil), samples...)
	mu.Unlock()

	resp := tailscalePingResponse{
		PeerIP:  peerIP,
		Samples: collected,
	}
	var sum float64
	var okCount int
	for _, s := range collected {
		if s.Error != "" {
			if resp.Error == "" {
				resp.Error = s.Error
			}
			continue
		}
		okCount++
		sum += s.LatencyMs
		if resp.MinMs == 0 || s.LatencyMs < resp.MinMs {
			resp.MinMs = s.LatencyMs
		}
		resp.LatencyMs = s.LatencyMs
		resp.IsDirect = s.IsDirect
		resp.Endpoint = s.Endpoint
		resp.PeerRelay = s.PeerRelay
		resp.DERPRegionID = s.DERPRegionID
		resp.DERPRegionCode = s.DERPRegionCode
	}
	if okCount > 0 {
		resp.AvgMs = sum / float64(okCount)
		resp.Error = ""
	} else if resp.Error == "" {
		resp.Error = "ping timed out"
	}
	writeCtrlJSON(w, http.StatusOK, resp)
}

func (c *coreControlServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c.tsEp == nil {
		http.Error(w, "tailscale endpoint inactive", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := c.tsEp.Logout(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeCtrlJSON(w, http.StatusOK, map[string]any{"logged_out": true})
}

func (c *coreControlServer) handleTaildropInbox(w http.ResponseWriter, _ *http.Request) {
	c.mu.RLock()
	inbox := c.lastInbox
	c.mu.RUnlock()
	if inbox.Files == nil {
		inbox.Files = []taildropFileSnapshot{}
	}
	writeCtrlJSON(w, http.StatusOK, inbox)
}

func (c *coreControlServer) handleTaildropSend(w http.ResponseWriter, r *http.Request) {
	if c.tsEp == nil {
		http.Error(w, "tailscale endpoint inactive", http.StatusServiceUnavailable)
		return
	}
	// Cap upload size to 512 MiB.
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	peerStableID := strings.TrimSpace(r.FormValue("peer_stable_id"))
	if peerStableID == "" {
		http.Error(w, "peer_stable_id is required", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	cleanName, err := sanitizeTaildropFileName(filepath.Base(header.Filename))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var sentBytes int64
	if err := c.tsEp.SendTaildropFile(r.Context(), peerStableID, cleanName, header.Size, file, func(n int64) {
		sentBytes = n
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeCtrlJSON(w, http.StatusOK, map[string]any{
		"sent":           true,
		"file_name":      cleanName,
		"peer_stable_id": peerStableID,
		"size":           header.Size,
		"sent_bytes":     sentBytes,
	})
}

func (c *coreControlServer) handleTaildropFile(w http.ResponseWriter, r *http.Request) {
	if c.tsEp == nil {
		http.Error(w, "tailscale endpoint inactive", http.StatusServiceUnavailable)
		return
	}
	// Go 1.22+ ServeMux already URL-unescapes PathValue("name"); avoid double-unescaping
	// so filenames containing literal '%' characters are preserved intact.
	cleanName, err := sanitizeTaildropFileName(r.PathValue("name"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodDelete {
		if err := c.tsEp.DeleteTaildropFile(cleanName); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rc, size, err := c.tsEp.OpenTaildropFile(cleanName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, cleanName))
	if size > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	}
	_, _ = io.Copy(w, rc)
}

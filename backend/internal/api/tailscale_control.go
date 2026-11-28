// SPDX-License-Identifier: MPL-2.0

package api

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
)

var coreControlTransport = &http.Transport{
	Proxy:               nil,
	MaxIdleConns:        16,
	MaxIdleConnsPerHost: 8,
	IdleConnTimeout:     60 * time.Second,
}

func (s *Server) coreControlRequest(ctx context.Context, method, path string, body io.Reader, contentType string, timeout time.Duration) (*http.Response, error) {
	addr, token := s.ensureOrchestrator().CoreControlEndpoint()
	if addr == "" || token == "" {
		return nil, &httpError{Code: http.StatusNotImplemented, Msg: "当前运行的 sing-box 核心不支持本地 Tailscale 实时控制接口（请使用 PrismRay 内置包装核）"}
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: coreControlTransport,
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+addr+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &httpError{Code: http.StatusNotImplemented, Msg: "无法连接本地 Tailscale 控制接口（外部上游 sing-box 不支持此操作）"}
	}
	return resp, nil
}

func (s *Server) handleTailscaleExitNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		StableID string `json:"stable_id"`
		ExitNode string `json:"exit_node"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stableID := strings.TrimSpace(req.StableID)
	exitNodeVal := strings.TrimSpace(req.ExitNode)

	// Try zero-restart live hot-switch via PrismRay's unified sing-box control server first.
	hotSwitched := false
	payload, _ := json.Marshal(map[string]string{"stable_id": stableID})
	if resp, err := s.coreControlRequest(r.Context(), http.MethodPost, "/tailscale/exit-node", bytes.NewReader(payload), "application/json", 12*time.Second); err == nil {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			hotSwitched = true
		} else if resp.StatusCode != http.StatusNotImplemented && resp.StatusCode != http.StatusServiceUnavailable {
			http.Error(w, strings.TrimSpace(string(raw)), resp.StatusCode)
			return
		}
	}

	// Persist exit_node preference so subsequent restarts preserve the selection.
	s.opMu.Lock()
	cfg, _ := s.tailscaleConfig(false)
	if exitNodeVal != "" {
		cfg.ExitNode = exitNodeVal
	} else if stableID == "" {
		cfg.ExitNode = ""
	}
	if s.store != nil {
		toSave := cfg
		toSave.AuthKey = ""
		toSave.HasAuthKey = false
		toSave.ClearAuthKey = false
		_ = s.store.PutSetting(tailscaleSettingKey, toSave)
	}
	var applyErr error
	if !hotSwitched && s.ensureOrchestrator().Status().Running && cfg.Enabled {
		rs := s.runtimeState()
		_, applyErr = s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, rs.tunEnabled)
	}
	s.opMu.Unlock()

	if applyErr != nil {
		respondError(w, applyErr, http.StatusBadGateway)
		return
	}
	saved, _ := s.tailscaleConfig(false)
	stateInit := s.tailscaleStateExists()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"hot_switched": hotSwitched,
		"config":       saved,
		"status":       s.tailscaleRuntimeStatus(saved, stateInit),
	})
}

func (s *Server) handleTailscalePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.coreControlRequest(r.Context(), http.MethodPost, "/tailscale/ping", bytes.NewReader(body), "application/json", 12*time.Second)
	if err != nil {
		respondError(w, err, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 256<<10))
}

func (s *Server) handleTailscaleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp, err := s.coreControlRequest(r.Context(), http.MethodPost, "/tailscale/logout", nil, "", 20*time.Second)
	if err != nil {
		respondError(w, err, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		http.Error(w, strings.TrimSpace(string(raw)), resp.StatusCode)
		return
	}
	cfg, _ := s.tailscaleConfig(false)
	stateInit := s.tailscaleStateExists()
	writeJSON(w, http.StatusOK, map[string]any{
		"logged_out": true,
		"status":     s.tailscaleRuntimeStatus(cfg, stateInit),
	})
}

func (s *Server) handleTaildropInbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp, err := s.coreControlRequest(r.Context(), http.MethodGet, "/tailscale/taildrop/inbox", nil, "", 8*time.Second)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"available":       false,
			"can_share_files": false,
			"files":           []any{},
			"receiving":       0,
		})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeJSON(w, http.StatusOK, map[string]any{
			"available":       false,
			"can_share_files": false,
			"files":           []any{},
			"receiving":       0,
		})
		return
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	payload["available"] = true
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleTaildropSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Extend per-request read deadline past the global 30s ReadTimeout so large Taildrop
	// file uploads (up to 512 MiB) do not abort mid-stream.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(10 * time.Minute))
	resp, err := s.coreControlRequest(
		r.Context(),
		http.MethodPost,
		"/tailscale/taildrop/send",
		r.Body,
		r.Header.Get("Content-Type"),
		10*time.Minute,
	)
	if err != nil {
		respondError(w, err, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}

func (s *Server) handleTaildropFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		http.Error(w, "file name required", http.StatusBadRequest)
		return
	}
	ctrlPath := "/tailscale/taildrop/file/" + url.PathEscape(name)
	resp, err := s.coreControlRequest(r.Context(), r.Method, ctrlPath, nil, "", 5*time.Minute)
	if err != nil {
		respondError(w, err, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if r.Method == http.MethodDelete {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		http.Error(w, strings.TrimSpace(string(raw)), resp.StatusCode)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		http.Error(w, strings.TrimSpace(string(raw)), resp.StatusCode)
		return
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		w.Header().Set("Content-Disposition", cd)
	} else {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name))
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

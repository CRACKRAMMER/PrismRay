// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/orchestrator"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func (s *Server) probeEnvOptions() (localDNS string, androidMode bool, protectPath string) {
	if profile, err := s.routingProfile(); err == nil && strings.TrimSpace(profile.LocalDNS) != "" {
		localDNS = strings.TrimSpace(profile.LocalDNS)
	}
	androidMode = s.mode == auth.ModeAndroid
	protectPath = s.effectiveProtectPath()
	return localDNS, androidMode, protectPath
}

const defaultProbeURL = "https://www.gstatic.com/generate_204"

func validateHTTPSProbeURL(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return defaultProbeURL, nil
	}
	u, err := url.ParseRequestURI(target)
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.Host == "" {
		return "", fmt.Errorf("health test url must use https://")
	}
	return u.String(), nil
}

func validateOptionalHTTPSURL(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", nil
	}
	u, err := url.ParseRequestURI(target)
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.Host == "" {
		return "", fmt.Errorf("speed test url must use https://")
	}
	return u.String(), nil
}

func normalizeProbeMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ping", "tcp":
		return "ping"
	case "speed", "bandwidth":
		return "speed"
	case "full", "all":
		return "full"
	default:
		return "urltest"
	}
}

func (s *Server) probeNodesAndPersist(
	ctx context.Context,
	targets []*config.Node,
	mode string,
	testURL string,
	speedDownURL string,
	speedUpURL string,
	timeout time.Duration,
) ([]orchestrator.ProbeResult, map[string]orchestrator.ProbeResult) {
	normMode := normalizeProbeMode(mode)
	var allNodes []*config.Node
	var allGroups []storage.Group
	if s.store != nil {
		allNodes = s.store.List()
		allGroups, _ = s.store.ListGroups()
	}
	localDNS, androidMode, protectPath := s.probeEnvOptions()
	rawResults := s.ensureOrchestrator().ProbeNodesWithOptions(ctx, targets, orchestrator.ProbeOptions{
		Mode:         normMode,
		TestURL:      testURL,
		SpeedDownURL: speedDownURL,
		SpeedUpURL:   speedUpURL,
		LocalDNS:     localDNS,
		AndroidMode:  androidMode,
		ProtectPath:  protectPath,
		Timeout:      timeout,
		AllNodes:     allNodes,
		AllGroups:    allGroups,
	})
	ordered := make([]orchestrator.ProbeResult, 0, len(targets))
	for _, n := range targets {
		res, ok := rawResults[n.ID]
		if !ok {
			res = orchestrator.ProbeResult{NodeID: n.ID, LatencyMS: -1, Mode: normMode, Error: "no probe result"}
		}
		if s.store != nil {
			var latPtr, pingPtr *int
			var downPtr, upPtr *float64
			switch normMode {
			case "ping":
				v := int(res.PingMS)
				if res.Error != "" && v == 0 {
					v = -1
				}
				pingPtr = &v
			case "speed":
				if res.DownSpeedMbps > 0 || res.Error == "" {
					v := res.DownSpeedMbps
					downPtr = &v
				}
				if res.UpSpeedMbps > 0 || res.Error == "" {
					v := res.UpSpeedMbps
					upPtr = &v
				}
				if res.Error != "" && res.DownSpeedMbps == 0 && res.UpSpeedMbps == 0 {
					v := -1
					latPtr = &v
				}
			case "full":
				lv := int(res.LatencyMS)
				if res.Error != "" && lv == 0 {
					lv = -1
				}
				pv := int(res.PingMS)
				if pv == 0 && res.Error != "" {
					pv = -1
				}
				dv := res.DownSpeedMbps
				uv := res.UpSpeedMbps
				latPtr = &lv
				pingPtr = &pv
				downPtr = &dv
				upPtr = &uv
			default:
				lv := int(res.LatencyMS)
				if res.Error != "" || lv < 0 {
					lv = -1
				}
				latPtr = &lv
			}
			_ = s.store.UpdateNodeProbeMetrics(n.ID, latPtr, pingPtr, downPtr, upPtr)
		}
		ordered = append(ordered, res)
	}
	return ordered, rawResults
}

func (s *Server) probe(ctx context.Context, n *config.Node, target string) (int64, error) {
	cleanURL, err := validateHTTPSProbeURL(target)
	if err != nil {
		return 0, err
	}
	if n == nil {
		return 0, fmt.Errorf("node is required")
	}
	_, results := s.probeNodesAndPersist(ctx, []*config.Node{n}, "urltest", cleanURL, "", "", 10*time.Second)
	res, ok := results[n.ID]
	if !ok {
		return 0, fmt.Errorf("probe produced no result for node %q", n.ID)
	}
	if res.Error != "" {
		return 0, fmt.Errorf("%s", res.Error)
	}
	return res.LatencyMS, nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	n := s.store.Get(id)
	if n == nil {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}
	var req struct {
		URL          string `json:"url"`
		Mode         string `json:"mode"`
		SpeedDownURL string `json:"speed_down_url"`
		SpeedUpURL   string `json:"speed_up_url"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	hs, _ := s.healthSettings()
	testURL := strings.TrimSpace(req.URL)
	if testURL == "" {
		testURL = hs.URL
	}
	cleanURL, err := validateHTTPSProbeURL(testURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	downURL := strings.TrimSpace(req.SpeedDownURL)
	if downURL == "" {
		downURL = hs.SpeedDownURL
	}
	upURL := strings.TrimSpace(req.SpeedUpURL)
	if upURL == "" {
		upURL = hs.SpeedUpURL
	}
	mode := normalizeProbeMode(req.Mode)
	ordered, _ := s.probeNodesAndPersist(r.Context(), []*config.Node{n}, mode, cleanURL, downURL, upURL, 10*time.Second)
	if len(ordered) == 0 {
		http.Error(w, "probe produced no result", http.StatusBadGateway)
		return
	}
	res := ordered[0]
	if res.Error != "" && mode == "urltest" {
		http.Error(w, res.Error, http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":              id,
		"node_id":         id,
		"latency_ms":      res.LatencyMS,
		"ping_ms":         res.PingMS,
		"down_speed_mbps": res.DownSpeedMbps,
		"up_speed_mbps":   res.UpSpeedMbps,
		"mode":            mode,
		"error":           res.Error,
	})
}

func (s *Server) handleProbeNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeIDs      []string `json:"node_ids,omitempty"`
		Mode         string   `json:"mode,omitempty"`
		URL          string   `json:"url,omitempty"`
		SpeedDownURL string   `json:"speed_down_url,omitempty"`
		SpeedUpURL   string   `json:"speed_up_url,omitempty"`
		TimeoutMS    int      `json:"timeout_ms,omitempty"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	hs, _ := s.healthSettings()
	testURL := strings.TrimSpace(req.URL)
	if testURL == "" {
		testURL = hs.URL
	}
	cleanURL, err := validateHTTPSProbeURL(testURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	downURL, err := validateOptionalHTTPSURL(req.SpeedDownURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if downURL == "" {
		downURL = hs.SpeedDownURL
	}
	upURL, err := validateOptionalHTTPSURL(req.SpeedUpURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if upURL == "" {
		upURL = hs.SpeedUpURL
	}
	timeout := 10 * time.Second
	if req.TimeoutMS >= 500 && req.TimeoutMS <= 30000 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}

	allNodes := s.store.List()
	var targets []*config.Node
	if len(req.NodeIDs) == 0 {
		targets = allNodes
	} else {
		want := make(map[string]bool, len(req.NodeIDs))
		for _, id := range req.NodeIDs {
			want[id] = true
		}
		for _, n := range allNodes {
			if want[n.ID] {
				targets = append(targets, n)
			}
		}
	}

	ordered, rawResults := s.probeNodesAndPersist(r.Context(), targets, req.Mode, cleanURL, downURL, upURL, timeout)

	writeJSON(w, http.StatusOK, map[string]any{
		"mode":    normalizeProbeMode(req.Mode),
		"results": ordered,
		"by_id":   rawResults,
		"tested":  len(ordered),
	})
}

func (s *Server) handleNodeTabs(w http.ResponseWriter, r *http.Request) {
	const settingKey = "proxies.custom_tabs"
	if r.Method == http.MethodGet {
		tabs := []string{}
		if s.store != nil {
			_, _ = s.store.GetSetting(settingKey, &tabs)
		}
		if tabs == nil {
			tabs = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"tabs": tabs})
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Tabs []string `json:"tabs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	seen := map[string]bool{}
	cleaned := make([]string, 0, len(payload.Tabs))
	for _, raw := range payload.Tabs {
		name := strings.TrimSpace(raw)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		cleaned = append(cleaned, name)
	}
	if s.store != nil {
		if err := s.store.PutSetting(settingKey, cleaned); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tabs": cleaned})
}

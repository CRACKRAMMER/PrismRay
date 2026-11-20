// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/orchestrator"
	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
)

const (
	defaultSpeedDownURL = "https://speed.cloudflare.com/__down?bytes=10000000"
	defaultSpeedUpURL   = "https://speed.cloudflare.com/__up"
)

// HealthSettings configures background connectivity monitoring, probing URLs, and group priority failover.
type HealthSettings struct {
	URL             string `json:"url"`
	SpeedDownURL    string `json:"speed_down_url"`
	SpeedUpURL      string `json:"speed_up_url"`
	IntervalSeconds int    `json:"interval_seconds"`
	ToleranceMS     int    `json:"tolerance_ms"`
	PriorityRule    string `json:"priority_rule"` // "latency_first" | "speed_first" | "hybrid_score"
	Failover        bool   `json:"failover"`
	Recover         bool   `json:"recover"`
}

func normalizePriorityRule(raw string) string {
	switch stringsTrim(raw) {
	case "speed_first", "hybrid_score", "latency_first":
		return stringsTrim(raw)
	default:
		return "latency_first"
	}
}

func (s *Server) healthSettings() (HealthSettings, error) {
	v := HealthSettings{
		URL:             defaultProbeURL,
		SpeedDownURL:    defaultSpeedDownURL,
		SpeedUpURL:      defaultSpeedUpURL,
		IntervalSeconds: 120,
		ToleranceMS:     50,
		PriorityRule:    "latency_first",
	}
	if s.store == nil {
		return v, nil
	}
	found, err := s.store.GetSetting("health.settings", &v)
	if err != nil {
		return v, err
	}
	if found && v.IntervalSeconds < 30 {
		v.IntervalSeconds = 120
	}
	if stringsTrim(v.URL) == "" {
		v.URL = defaultProbeURL
	}
	if stringsTrim(v.SpeedDownURL) == "" {
		v.SpeedDownURL = defaultSpeedDownURL
	}
	if stringsTrim(v.SpeedUpURL) == "" {
		v.SpeedUpURL = defaultSpeedUpURL
	}
	if v.ToleranceMS <= 0 {
		v.ToleranceMS = 50
	}
	v.PriorityRule = normalizePriorityRule(v.PriorityRule)
	return v, nil
}

func stringsTrim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}

func (s *Server) handleHealthSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		v, err := s.healthSettings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, v)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var v HealthSettings
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cleanURL, err := validateHTTPSProbeURL(v.URL)
	if err != nil || v.IntervalSeconds < 30 {
		http.Error(w, "需要 HTTPS 测试地址，间隔至少 30 秒", http.StatusBadRequest)
		return
	}
	downURL, err := validateOptionalHTTPSURL(v.SpeedDownURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	upURL, err := validateOptionalHTTPSURL(v.SpeedUpURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v.URL = cleanURL
	if downURL != "" {
		v.SpeedDownURL = downURL
	} else {
		v.SpeedDownURL = defaultSpeedDownURL
	}
	if upURL != "" {
		v.SpeedUpURL = upURL
	} else {
		v.SpeedUpURL = defaultSpeedUpURL
	}
	if v.ToleranceMS < 0 {
		v.ToleranceMS = 50
	}
	v.PriorityRule = normalizePriorityRule(v.PriorityRule)
	if err := s.store.PutSetting("health.settings", v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) activate(n *config.Node) error {
	if n == nil {
		return fmt.Errorf("node is nil")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	_, err := s.reconcileRuntime(context.Background(), n.ID, "", s.tunEnabled)
	return err
}

func (s *Server) maintainHealth(ctx context.Context) {
	v, err := s.healthSettings()
	if err != nil {
		return
	}
	if v.IntervalSeconds < 30 {
		v.IntervalSeconds = 120
	}
	if !s.lastHealth.IsZero() && time.Since(s.lastHealth) < time.Duration(v.IntervalSeconds)*time.Second {
		return
	}
	s.lastHealth = time.Now()
	if err := s.refreshListenerHealth(ctx, v); err != nil {
		s.listenerHealth = err.Error()
	} else {
		s.listenerHealth = ""
	}
	if !v.Failover && !v.Recover {
		return
	}

	s.opMu.Lock()
	activeID := s.activeNodeID
	activeGroupID := s.activeGroupID
	running := s.ensureOrchestrator().Status().Running
	s.opMu.Unlock()
	if !s.wantRunning {
		return
	}

	if v.Recover && !running && (activeID != "" || activeGroupID != "") {
		if activeGroupID != "" {
			s.opMu.Lock()
			_, _ = s.reconcileRuntime(context.Background(), "", activeGroupID, s.tunEnabled)
			s.opMu.Unlock()
		} else if n := s.store.Get(activeID); n != nil {
			_ = s.activate(n)
		}
	}

	if !v.Failover {
		if activeGroupID != "" {
			if groups, err := s.store.ListGroups(); err == nil {
				for _, g := range groups {
					if g.ID == activeGroupID && effectiveGroupAutoFailover(g, false) {
						_, _, _, _ = s.probeAndReorderGroup(ctx, activeGroupID, "urltest", "", v, false)
						return
					}
				}
			}
		}
		return
	}
	if activeGroupID != "" {
		_, _, _, _ = s.probeAndReorderGroup(ctx, activeGroupID, "urltest", "", v, false)
		return
	}
	if activeID == "" {
		return
	}
	activeNode := s.store.Get(activeID)
	if activeNode == nil {
		return
	}
	if _, err := s.probe(ctx, activeNode, v.URL); err == nil {
		return
	}

	candidates := []*config.Node{}
	for _, n := range s.store.List() {
		if n.ID != activeID {
			candidates = append(candidates, n)
		}
	}
	if len(candidates) == 0 {
		return
	}
	allNodes := s.store.List()
	allGroups, _ := s.store.ListGroups()
	localDNS, androidMode, protectPath := s.probeEnvOptions()
	results := s.ensureOrchestrator().ProbeNodesWithOptions(ctx, candidates, orchestrator.ProbeOptions{
		Mode:        "urltest",
		TestURL:     v.URL,
		LocalDNS:    localDNS,
		AndroidMode: androidMode,
		ProtectPath: protectPath,
		Timeout:     8 * time.Second,
		AllNodes:    allNodes,
		AllGroups:   allGroups,
	})
	var best *config.Node
	var bestMS int64 = 1<<62 - 1
	for _, c := range candidates {
		res, ok := results[c.ID]
		if ok && res.Error == "" && res.LatencyMS >= 0 {
			_ = s.store.UpdateLatency(c.ID, int(res.LatencyMS))
			if res.LatencyMS < bestMS {
				bestMS = res.LatencyMS
				best = c
			}
		}
	}
	if best != nil {
		_ = s.activate(best)
	}
}

func (s *Server) refreshListenerHealth(ctx context.Context, v HealthSettings) error {
	listeners := s.store.ListListeners()
	var needed []*config.Node
	seen := map[string]bool{}
	for _, l := range listeners {
		if !l.Enabled {
			continue
		}
		for _, id := range l.NodeIDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			if n := s.store.Get(id); n != nil {
				needed = append(needed, n)
			}
		}
	}
	if len(needed) == 0 {
		return nil
	}
	allNodes := s.store.List()
	allGroups, _ := s.store.ListGroups()
	localDNS, androidMode, protectPath := s.probeEnvOptions()
	results := s.ensureOrchestrator().ProbeNodesWithOptions(ctx, needed, orchestrator.ProbeOptions{
		Mode:        "urltest",
		TestURL:     v.URL,
		LocalDNS:    localDNS,
		AndroidMode: androidMode,
		ProtectPath: protectPath,
		Timeout:     8 * time.Second,
		AllNodes:    allNodes,
		AllGroups:   allGroups,
	})
	for _, n := range needed {
		if res, ok := results[n.ID]; ok && res.Error == "" && res.LatencyMS >= 0 {
			_ = s.store.UpdateLatency(n.ID, int(res.LatencyMS))
		}
	}
	return nil
}

func (s *Server) setKillSwitchBaseline(activeTag string) {
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	if activeTag != "" && activeTag != sbcfg.BlockOutboundTag {
		s.intendedActiveTag = activeTag
	}
	s.killSwitchTripped = false
	s.killSwitchFailures = 0
	s.killSwitchReason = ""
}

func (s *Server) setKillSwitchTripped(intendedTag, reason string) {
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	if intendedTag != "" && intendedTag != sbcfg.BlockOutboundTag {
		s.intendedActiveTag = intendedTag
	}
	s.killSwitchTripped = true
	s.killSwitchReason = reason
}

func (s *Server) clearKillSwitch() {
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	s.intendedActiveTag = ""
	s.killSwitchTripped = false
	s.killSwitchFailures = 0
	s.killSwitchReason = ""
}

func (s *Server) killSwitchSnapshot() (bool, string, string) {
	s.ksMu.RLock()
	defer s.ksMu.RUnlock()
	return s.killSwitchTripped, s.killSwitchReason, s.intendedActiveTag
}

func (s *Server) resetKillSwitchFailures() bool {
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	wasTripped := s.killSwitchTripped
	s.killSwitchFailures = 0
	if wasTripped {
		s.killSwitchTripped = false
		s.killSwitchReason = ""
	}
	return wasTripped
}

func (s *Server) incrementKillSwitchFailures() int {
	s.ksMu.Lock()
	defer s.ksMu.Unlock()
	s.killSwitchFailures++
	return s.killSwitchFailures
}

func (s *Server) maintainKillSwitch(ctx context.Context) {
	orch := s.ensureOrchestrator()
	clash := orch.ClashClient()
	var probeFn func(context.Context, string, string, int) (int, error)
	if clash != nil {
		probeFn = clash.ProbeDelay
	}
	s.evaluateKillSwitchOnce(ctx, probeFn)
}

func (s *Server) evaluateKillSwitchOnce(ctx context.Context, probeDelay func(context.Context, string, string, int) (int, error)) {
	profile, err := s.routingProfile()
	if err != nil {
		return
	}

	s.opMu.Lock()
	wantRunning := s.wantRunning
	activeNodeID := s.activeNodeID
	activeGroupID := s.activeGroupID
	tunEnabled := s.tunEnabled
	s.opMu.Unlock()

	orch := s.ensureOrchestrator()
	st := orch.Status()

	if !wantRunning || profile.Mode == "direct" || !profile.KillSwitchEnabled() {
		if tripped, _, intended := s.killSwitchSnapshot(); tripped {
			if wantRunning && st.Running && intended != "" {
				_ = orch.HotSwitch(ctx, "proxy", intended)
			}
			s.clearKillSwitch()
		}
		return
	}

	if !st.Running {
		var recErr error
		s.opMu.Lock()
		if s.wantRunning && !orch.Status().Running {
			_, recErr = s.reconcileRuntime(ctx, activeNodeID, activeGroupID, tunEnabled)
		}
		s.opMu.Unlock()
		if recErr != nil {
			s.setKillSwitchTripped("", "代理核心异常退出，Kill Switch 已激活防直连保护")
			orch.AppendLog("system", "error", "Kill Switch active after unexpected core exit: "+recErr.Error())
		}
		return
	}

	_, _, intended := s.killSwitchSnapshot()
	probeTag := intended
	if probeTag == "" && st.ActiveTag != sbcfg.BlockOutboundTag {
		probeTag = st.ActiveTag
	}
	if probeTag == "" || probeTag == sbcfg.BlockOutboundTag {
		if st.ActiveTag == sbcfg.BlockOutboundTag {
			s.setKillSwitchTripped("", "无可用代理出站，Kill Switch 已阻断代理流量防止直连泄漏")
		}
		return
	}
	if probeDelay == nil {
		return
	}

	hs, _ := s.healthSettings()
	testURL := hs.URL
	if stringsTrim(testURL) == "" {
		testURL = defaultProbeURL
	}
	delay, probeErr := probeDelay(ctx, probeTag, testURL, 5000)
	if probeErr == nil && delay > 0 {
		if s.resetKillSwitchFailures() {
			if err := orch.HotSwitch(ctx, "proxy", probeTag); err == nil {
				s.setKillSwitchBaseline(probeTag)
				orch.AppendLog("system", "info", fmt.Sprintf("Kill Switch 已恢复：主代理已切回 %s (%dms)", probeTag, delay))
			}
		}
		return
	}

	failures := s.incrementKillSwitchFailures()
	if failures < 2 {
		return
	}

	if tripped, _, _ := s.killSwitchSnapshot(); !tripped {
		reason := fmt.Sprintf("当前代理出站 (%s) 连续探测不可达，已自动断网阻断代理流量防止直连泄漏", probeTag)
		s.setKillSwitchTripped(probeTag, reason)
		orch.AppendLog("system", "error", reason)
		_ = orch.HotSwitch(ctx, "proxy", sbcfg.BlockOutboundTag)
		if clash := orch.ClashClient(); clash != nil {
			_ = clash.CloseAllConnections(ctx)
		}
	}
}

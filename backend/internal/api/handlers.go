// SPDX-License-Identifier: MPL-2.0

package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/orchestrator"
	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/tun"
	"github.com/gorilla/websocket"
)

func newRandomID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err == nil {
		return prefix + hex.EncodeToString(b)
	}
	return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano())
}

func (s *Server) buildStatusPayload() map[string]any {
	st := s.ensureOrchestrator().Status()
	profile, err := s.routingProfile()
	mode := "rule"
	if err == nil && profile.Mode != "" {
		mode = profile.Mode
	}
	ksTripped, ksReason, _ := s.killSwitchSnapshot()
	statusStr := "stopped"
	if st.Running {
		statusStr = "running"
	}
	activeNodeID := s.activeNodeID
	if activeNodeID == "" {
		activeNodeID = st.ActiveNodeID
	}
	activeGroupID := s.activeGroupID
	if activeGroupID == "" {
		activeGroupID = st.ActiveGroupID
	}
	activeNodeName := ""
	if activeNodeID != "" {
		if n := s.store.Get(activeNodeID); n != nil {
			activeNodeName = strings.TrimSpace(n.Name)
		}
	}
	activeGroupName := ""
	if activeGroupID != "" {
		if groups, gErr := s.store.ListGroups(); gErr == nil {
			for _, g := range groups {
				if g.ID == activeGroupID {
					activeGroupName = strings.TrimSpace(g.Name)
					break
				}
			}
		}
	}
	return map[string]any{
		"status":               statusStr,
		"running":              st.Running,
		"singbox_running":      st.SingBoxRunning,
		"xray_running":         st.XrayRunning,
		"singbox_pid":          st.SingBoxPID,
		"xray_pid":             st.XrayPID,
		"active_node_id":       activeNodeID,
		"active_group_id":      activeGroupID,
		"active_node_name":     activeNodeName,
		"active_group_name":    activeGroupName,
		"active_tag":           st.ActiveTag,
		"tun_enabled":          st.TUNEnabled,
		"android_mode":         st.AndroidMode,
		"mixed_port":           st.MixedPort,
		"clash_api_port":       st.ClashAPIPort,
		"uptime_seconds":       st.UptimeSeconds,
		"last_error":           st.LastError,
		"skipped_naive":        st.SkippedNaive,
		"resolved_singbox":     st.ResolvedSingBox,
		"resolved_xray":        st.ResolvedXray,
		"listener_health":      s.listenerHealth,
		"mode":                 mode,
		"system_proxy_enabled": s.proxyManager().Active(),
		"system_proxy_wanted":  s.systemProxyWanted,
		"kill_switch_enabled":  profile.KillSwitchEnabled(),
		"kill_switch_tripped":  ksTripped,
		"kill_switch_reason":   ksReason,
	}
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	s.opMu.Lock()
	st, err := s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled)
	s.opMu.Unlock()
	if err != nil {
		respondError(w, err, http.StatusBadGateway)
		return
	}
	if s.systemProxyWanted && st.Running && st.MixedPort > 0 && !s.proxyManager().Active() {
		_ = s.proxyManager().Enable(st.MixedPort)
	}
	writeJSON(w, http.StatusOK, s.buildStatusPayload())
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	wasTUN := s.ensureOrchestrator().Status().TUNEnabled
	s.persistWantRunning(false)
	s.clearKillSwitch()
	if err := s.ensureOrchestrator().Stop(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if wasTUN {
		_ = tun.CleanupStaleRoutes(r.Context(), s.effectiveSudoPassword())
	}
	if s.proxyManager().Active() {
		_ = s.RestoreSystemProxy()
	}
	writeJSON(w, http.StatusOK, s.buildStatusPayload())
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	_ = s.ensureOrchestrator().Stop()
	st, err := s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled)
	if err != nil {
		respondError(w, err, http.StatusBadGateway)
		return
	}
	if s.systemProxyWanted && st.Running && st.MixedPort > 0 && s.mode != authservice.ModeAndroid && !s.proxyManager().Active() {
		_ = s.proxyManager().Enable(st.MixedPort)
	}
	writeJSON(w, http.StatusOK, s.buildStatusPayload())
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.buildStatusPayload())
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !websocket.IsWebSocketUpgrade(r) {
		writeJSON(w, http.StatusOK, s.ensureOrchestrator().LogHistory(200))
		return
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(req *http.Request) bool { return s.originAllowed(req) },
	}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()

	orch := s.ensureOrchestrator()
	ch, unsub := orch.SubscribeLogs()
	defer unsub()

	disconnected := watchDisconnect(c)
	var lastSeq uint64
	for _, entry := range orch.LogHistory(200) {
		lastSeq = entry.Seq
		if err := c.WriteJSON(entry); err != nil {
			return
		}
	}
	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return
			}
			if entry.Seq <= lastSeq {
				continue
			}
			lastSeq = entry.Seq
			if err := c.WriteJSON(entry); err != nil {
				return
			}
		case <-disconnected:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if !websocket.IsWebSocketUpgrade(r) {
		client := s.ensureOrchestrator().ClashClient()
		if client == nil {
			writeJSON(w, http.StatusOK, map[string]int64{"up": 0, "down": 0})
			return
		}
		snap, err := client.GetConnections(r.Context())
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]int64{"up": 0, "down": 0})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{
			"up":             0,
			"down":           0,
			"upload_total":   snap.UploadTotal,
			"download_total": snap.DownloadTotal,
		})
		return
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(req *http.Request) bool { return s.originAllowed(req) },
	}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()

	disconnected := watchDisconnect(c)
	orch := s.ensureOrchestrator()

	for {
		client := orch.ClashClient()
		if client != nil {
			streamCtx := r.Context()
			ch, errCh := client.StreamTraffic(streamCtx)
			closed := false
			for !closed {
				select {
				case frame, ok := <-ch:
					if !ok {
						closed = true
						break
					}
					if err := c.WriteJSON(map[string]any{
						"up":        frame.Up,
						"down":      frame.Down,
						"timestamp": time.Now().UnixMilli(),
					}); err != nil {
						return
					}
				case <-errCh:
					closed = true
				case <-disconnected:
					return
				case <-r.Context().Done():
					return
				}
			}
		}

		if err := c.WriteJSON(map[string]any{
			"up":        int64(0),
			"down":      int64(0),
			"timestamp": time.Now().UnixMilli(),
		}); err != nil {
			return
		}
		select {
		case <-time.After(1 * time.Second):
		case <-disconnected:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request)     { s.applyNode(w, r, true) }
func (s *Server) handleApplyConfig(w http.ResponseWriter, r *http.Request) { s.applyNode(w, r, false) }

func (s *Server) applyNode(w http.ResponseWriter, r *http.Request, connect bool) {
	var req struct {
		NodeID  string       `json:"node_id"`
		GroupID string       `json:"group_id"`
		Node    *config.Node `json:"node"`
	}
	if r.Body != nil {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(strings.TrimSpace(string(raw))) > 0 {
			if err := json.Unmarshal(raw, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	targetNodeID := strings.TrimSpace(req.NodeID)
	targetGroupID := strings.TrimSpace(req.GroupID)

	if req.Node != nil {
		if err := s.validateCandidateNode(req.Node); err != nil {
			respondError(w, err, http.StatusBadRequest)
			return
		}
		node := req.Node
		if strings.TrimSpace(node.ID) == "" {
			node.ID = newRandomID("node-")
		}
		existing := s.store.Get(node.ID)
		if existing != nil {
			if err := s.store.Update(node); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			if err := s.store.Add(node); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		targetNodeID = node.ID
		targetGroupID = ""
	}

	if targetNodeID != "" {
		if s.store.Get(targetNodeID) == nil {
			http.Error(w, "node not found", http.StatusBadRequest)
			return
		}
		targetGroupID = ""
	} else if targetGroupID != "" {
		groups, err := s.store.ListGroups()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		found := false
		for _, g := range groups {
			if g.ID == targetGroupID {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "group not found", http.StatusBadRequest)
			return
		}
	} else {
		targetNodeID = s.activeNodeID
		targetGroupID = s.activeGroupID
		if targetNodeID == "" && targetGroupID == "" {
			nodes := s.store.List()
			if len(nodes) > 0 {
				targetNodeID = nodes[0].ID
			}
		}
	}

	// Preserve existing behavior: connect always ensures running; apply also starts/reloads runtime
	// so config changes take effect atomically and invalid configs fail before replacing running state.
	_ = connect
	st, err := s.reconcileRuntime(r.Context(), targetNodeID, targetGroupID, s.tunEnabled)
	if err != nil {
		respondError(w, err, http.StatusBadGateway)
		return
	}
	if s.systemProxyWanted && st.Running && st.MixedPort > 0 && !s.proxyManager().Active() {
		_ = s.proxyManager().Enable(st.MixedPort)
	}
	writeJSON(w, http.StatusOK, s.buildStatusPayload())
}

func (s *Server) handleGetServerConfig(w http.ResponseWriter, _ *http.Request) {
	if s.cfg == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"server": s.cfg.Server,
		"sing_box": map[string]any{
			"mixed_port":     s.cfg.SingBox.MixedPort,
			"clash_api_port": s.cfg.SingBox.ClashAPIPort,
			"rule_set_dir":   s.cfg.SingBox.RuleSetDir,
			"auto_update":    s.cfg.SingBox.AutoUpdate,
		},
		"xray": map[string]any{
			"socks_port":  s.cfg.Xray.SocksPort,
			"stats_port":  s.cfg.Xray.StatsPort,
			"auto_update": s.cfg.Xray.AutoUpdate,
		},
		"storage": s.cfg.Storage,
	})
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	groupID := strings.TrimSpace(r.URL.Query().Get("group"))
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
	if search == "" {
		search = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	}
	var allowedIDs map[string]bool
	if groupID != "" {
		groups, err := s.store.ListGroups()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, g := range groups {
			if g.ID == groupID {
				allowedIDs = make(map[string]bool, len(g.NodeIDs))
				for _, id := range g.NodeIDs {
					allowedIDs[id] = true
				}
				break
			}
		}
		if allowedIDs == nil {
			writeJSON(w, http.StatusOK, []*config.Node{})
			return
		}
	}

	nodes := s.store.List()
	filtered := make([]*config.Node, 0, len(nodes))
	for _, n := range nodes {
		if allowedIDs != nil && !allowedIDs[n.ID] {
			continue
		}
		if search != "" && !matchesNodeSearch([]string{n.DisplayName(), n.Name, n.UserAlias, n.Address, string(n.Protocol), n.SubID}, search) {
			continue
		}
		filtered = append(filtered, n)
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) clearDetourReferences(deletedID string) {
	deletedID = strings.TrimSpace(deletedID)
	if deletedID == "" || s.store == nil {
		return
	}
	for _, n := range s.store.List() {
		if n != nil && strings.TrimSpace(n.DetourID) == deletedID {
			copyNode := *n
			copyNode.DetourID = ""
			_ = s.store.Update(&copyNode)
		}
	}
	if groups, err := s.store.ListGroups(); err == nil {
		for _, g := range groups {
			if strings.TrimSpace(g.DetourID) == deletedID {
				g.DetourID = ""
				_ = s.store.SaveGroup(g)
			}
		}
	}
}

func (s *Server) validateNodeDetour(candidate *config.Node) error {
	if candidate == nil || s.store == nil {
		return nil
	}
	nodes := s.store.List()
	replaced := false
	for i, existing := range nodes {
		if existing != nil && existing.ID == candidate.ID && candidate.ID != "" {
			nodes[i] = candidate
			replaced = true
			break
		}
	}
	if !replaced {
		nodes = append(nodes, candidate)
	}
	groups, err := s.store.ListGroups()
	if err != nil {
		return err
	}
	if strings.TrimSpace(candidate.DetourID) != "" {
		if err := sbcfg.ValidateDetourTarget(candidate.ID, candidate.DetourID, nodes, groups); err != nil {
			return err
		}
	}
	return sbcfg.ValidateAllDetours(nodes, groups)
}

func (s *Server) handleAddNode(w http.ResponseWriter, r *http.Request) {
	var node config.Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := node.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(node.ID) == "" {
		node.ID = newRandomID("node-")
	}
	node.DetourID = strings.TrimSpace(node.DetourID)
	if err := s.validateNodeDetour(&node); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.Add(&node); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, &node)
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var node config.Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	node.ID = id
	node.DetourID = strings.TrimSpace(node.DetourID)
	if err := node.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.validateNodeDetour(&node); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.store.Update(&node)
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.ensureOrchestrator().Status().Running {
		s.opMu.Lock()
		_, _ = s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled)
		s.opMu.Unlock()
	}
	writeJSON(w, http.StatusOK, &node)
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.Delete(id); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.clearDetourReferences(id)
	if s.activeNodeID == id {
		s.activeNodeID = ""
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n := s.store.Get(id)
	if n == nil {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}
	ms, err := s.probe(r.Context(), n, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "latency_ms": ms})
}

func (s *Server) handleImportSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL     string `json:"url"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rawContent := req.Content
	var meta config.SubscriptionTrafficMeta
	if strings.TrimSpace(rawContent) == "" && strings.TrimSpace(req.URL) != "" {
		parsedURL, err := url.ParseRequestURI(strings.TrimSpace(req.URL))
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			http.Error(w, "subscription url must be http or https", http.StatusBadRequest)
			return
		}
		client := safeHTTPClient(20 * time.Second)
		request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, parsedURL.String(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request.Header.Set("User-Agent", "PrismRay/1.0.0")
		resp, err := client.Do(request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			http.Error(w, fmt.Sprintf("subscription returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
			return
		}
		if info := resp.Header.Get("Subscription-Userinfo"); info != "" {
			meta = config.ParseUserinfoHeader(info)
		}
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		rawContent = string(bodyBytes)
	}

	res, err := config.ParseSubscriptionResilient(rawContent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(res.Nodes) == 0 {
		msg := "no supported nodes found"
		if len(res.Skipped) > 0 {
			msg = res.Skipped[0].Reason
		}
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	for _, n := range res.Nodes {
		if strings.TrimSpace(n.ID) == "" {
			n.ID = newRandomID("node-")
		}
	}
	if err := s.store.AddMultiple(res.Nodes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if meta.TotalBytes > 0 || meta.UploadBytes > 0 || meta.DownloadBytes > 0 || meta.ExpireUnix > 0 {
		res.Meta = meta
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"imported": len(res.Nodes),
		"nodes":    res.Nodes,
		"skipped":  res.Skipped,
		"warnings": res.Warnings,
		"meta":     res.Meta,
	})
}

func (s *Server) handleDownloadXray(w http.ResponseWriter, r *http.Request) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if s.ensureOrchestrator().Status().Running {
		http.Error(w, "请先停止代理和 TUN 再更换核心", http.StatusConflict)
		return
	}
	version, binary, err := s.installCore(r.Context(), "xray", "latest", true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.SetXrayPath(binary)
	writeJSON(w, http.StatusOK, map[string]any{
		"version": version,
		"path":    binary,
	})
}

func (s *Server) handleListListeners(w http.ResponseWriter, _ *http.Request) {
	listeners := s.store.ListListeners()
	if listeners == nil {
		listeners = []*config.ListenConfig{}
	}
	writeJSON(w, http.StatusOK, listeners)
}

func (s *Server) validateListener(lis *config.ListenConfig, replacing string) error {
	lis.Protocol = strings.ToLower(strings.TrimSpace(lis.Protocol))
	if lis.Protocol != "mixed" && lis.Protocol != "socks" && lis.Protocol != "http" {
		return fmt.Errorf("protocol must be mixed, socks, or http")
	}
	if lis.Port < 1 || lis.Port > 65535 {
		return fmt.Errorf("port must be 1..65535")
	}
	if s.cfg != nil && lis.Port == s.cfg.Server.Port {
		return fmt.Errorf("port conflicts with control-plane server port")
	}
	if strings.TrimSpace(lis.Address) == "" {
		if lis.AllowLAN {
			lis.Address = "0.0.0.0"
		} else {
			lis.Address = "127.0.0.1"
		}
	}
	for _, existing := range s.store.ListListeners() {
		if existing.ID != replacing && existing.Enabled && lis.Enabled && existing.Port == lis.Port {
			return fmt.Errorf("port already in use by another listener")
		}
	}
	lis.TargetOutbound = strings.ToLower(strings.TrimSpace(lis.TargetOutbound))
	if lis.TargetOutbound != "" && lis.TargetOutbound != "proxy" && lis.TargetOutbound != "direct" {
		return fmt.Errorf("target_outbound must be empty, proxy, or direct")
	}
	if targetGroup := strings.TrimSpace(lis.TargetGroupID); targetGroup != "" {
		groups, err := s.store.ListGroups()
		if err != nil {
			return err
		}
		found := false
		for _, g := range groups {
			if g.ID == targetGroup {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("target group %q does not exist", targetGroup)
		}
	}
	for _, nid := range lis.NodeIDs {
		if s.store.Get(nid) == nil {
			return fmt.Errorf("node %q does not exist", nid)
		}
	}
	return nil
}

func (s *Server) handleAddListener(w http.ResponseWriter, r *http.Request) {
	var lis config.ListenConfig
	if err := json.NewDecoder(r.Body).Decode(&lis); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.validateListener(&lis, ""); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(lis.ID) == "" {
		lis.ID = newRandomID("lis-")
	}
	if err := s.store.AddListener(&lis); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, &lis)
}

func (s *Server) handleUpdateListener(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var lis config.ListenConfig
	if err := json.NewDecoder(r.Body).Decode(&lis); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	lis.ID = id
	if err := s.validateListener(&lis, id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.store.UpdateListener(&lis)
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "listener not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.ensureOrchestrator().Status().Running {
		s.opMu.Lock()
		_, _ = s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled)
		s.opMu.Unlock()
	}
	writeJSON(w, http.StatusOK, &lis)
}

func (s *Server) handleDeleteListener(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.store.DeleteListener(id)
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "listener not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleApplyListeners(w http.ResponseWriter, r *http.Request) {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	listeners := s.store.ListListeners()
	if len(listeners) == 0 {
		http.Error(w, "no listeners configured", http.StatusBadRequest)
		return
	}
	if _, err := s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled); err != nil {
		respondError(w, err, http.StatusBadGateway)
		return
	}
	s.listenerHealth = ""
	writeJSON(w, http.StatusOK, s.buildStatusPayload())
}

func (s *Server) validateCandidate(data []byte) error {
	orch := s.ensureOrchestrator()
	sbBin, err := orch.ResolveSingBoxBinary()
	if err != nil {
		return err
	}
	tmp := filepath.Join(os.TempDir(), "prismray-check-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".json")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if out, checkErr := exec.Command(sbBin, "check", "-c", tmp).CombinedOutput(); checkErr != nil {
		return fmt.Errorf("sing-box check failed: %w (%s)", checkErr, strings.TrimSpace(string(out)))
	}
	return nil
}

func watchDisconnect(c *websocket.Conn) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}()
	return ch
}

// Keep unused slice import satisfied if needed in helpers.
var _ = slices.Contains[[]string, string]
var _ = orchestrator.Status{}

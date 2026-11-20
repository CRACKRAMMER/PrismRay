// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/orchestrator"
	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		groups, err := s.store.ListGroups()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, groups)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var group storage.Group
	if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(group.ID) == "" {
		group.ID = newRandomID("grp-")
	}
	group.DetourID = strings.TrimSpace(group.DetourID)
	if err := sbcfg.ValidateGroupInterval(group.Interval); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if existingGroups, err := s.store.ListGroups(); err == nil {
		candidateGroups := append(existingGroups, group)
		if vErr := sbcfg.ValidateAllDetours(s.store.List(), candidateGroups); vErr != nil {
			http.Error(w, vErr.Error(), http.StatusBadRequest)
			return
		}
	}
	if group.SortOrder <= 0 {
		if existing, listErr := s.store.ListGroups(); listErr == nil {
			group.SortOrder = len(existing) + 1
		}
	}
	if err := s.store.SaveGroup(group); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.ensureOrchestrator().Status().Running {
		s.opMu.Lock()
		_, _ = s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled)
		s.opMu.Unlock()
	}
	writeJSON(w, http.StatusOK, group)
}

func (s *Server) handleReorderGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		GroupIDs []string `json:"group_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.ReorderGroups(req.GroupIDs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.ensureOrchestrator().Status().Running {
		s.opMu.Lock()
		_, _ = s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled)
		s.opMu.Unlock()
	}
	groups, err := s.store.ListGroups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

func (s *Server) handleGroup(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "group id required", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodDelete {
		err := s.store.DeleteGroup(id)
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "group not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.clearDetourReferences(id)
		if s.activeGroupID == id {
			s.activeGroupID = ""
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var group storage.Group
	if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	group.ID = id
	group.DetourID = strings.TrimSpace(group.DetourID)
	if err := sbcfg.ValidateGroupInterval(group.Interval); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Ensure updating this group cannot introduce any node/group detour cycle (including 3-hop chains)
	// or turn an active detour group into loadbalance.
	if existingGroups, err := s.store.ListGroups(); err == nil {
		candidateGroups := make([]storage.Group, 0, len(existingGroups)+1)
		replaced := false
		for _, eg := range existingGroups {
			if eg.ID == group.ID {
				candidateGroups = append(candidateGroups, group)
				replaced = true
			} else {
				candidateGroups = append(candidateGroups, eg)
			}
		}
		if !replaced {
			candidateGroups = append(candidateGroups, group)
		}
		if vErr := sbcfg.ValidateAllDetours(s.store.List(), candidateGroups); vErr != nil {
			http.Error(w, vErr.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := s.store.SaveGroup(group); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.ensureOrchestrator().Status().Running {
		s.opMu.Lock()
		_, _ = s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled)
		s.opMu.Unlock()
	}
	writeJSON(w, http.StatusOK, group)
}

func (s *Server) handleGroupSelect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	groupID := strings.TrimSpace(r.PathValue("id"))
	if groupID == "" {
		http.Error(w, "group id required", http.StatusBadRequest)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.NodeID = strings.TrimSpace(req.NodeID)
	if req.NodeID == "" || s.store.Get(req.NodeID) == nil {
		http.Error(w, "node not found", http.StatusBadRequest)
		return
	}

	groups, err := s.store.ListGroups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var foundGroup *storage.Group
	for i := range groups {
		if groups[i].ID == groupID {
			foundGroup = &groups[i]
			break
		}
	}
	if foundGroup == nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}

	if err := s.store.SelectGroupNode(groupID, req.NodeID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()
	orch := s.ensureOrchestrator()
	if orch.Status().Running {
		memberTag := sbcfg.NodeTag(req.NodeID)
		if strings.TrimSpace(foundGroup.DetourID) != "" {
			if selNode := s.store.Get(req.NodeID); selNode != nil && !selNode.RequiresXray() {
				memberTag = sbcfg.GroupScopedNodeTag(req.NodeID, groupID)
			}
		}
		if err := orch.HotSwitch(r.Context(), sbcfg.GroupTag(groupID), memberTag); err != nil {
			if _, applyErr := s.reconcileRuntime(r.Context(), s.activeNodeID, groupID, s.tunEnabled); applyErr != nil {
				respondError(w, applyErr, http.StatusBadGateway)
				return
			}
		} else if s.activeGroupID == "" || s.activeGroupID == groupID {
			// Also steer top-level "proxy" selector to this group when active.
			if err := orch.HotSwitch(r.Context(), "proxy", sbcfg.GroupTag(groupID)); err == nil {
				s.setKillSwitchBaseline(sbcfg.GroupTag(groupID))
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"group_id": groupID,
		"node_id":  req.NodeID,
	})
}

func effectiveProbeLatency(n *config.Node, res orchestrator.ProbeResult, hasRes bool) int64 {
	if hasRes {
		if res.Error != "" {
			return -1
		}
		if res.LatencyMS > 0 {
			return res.LatencyMS
		}
		if res.PingMS > 0 {
			return res.PingMS
		}
	}
	if n != nil {
		if n.Latency > 0 {
			return int64(n.Latency)
		}
		if n.PingMS > 0 {
			return int64(n.PingMS)
		}
		if n.Latency < 0 {
			return -1
		}
	}
	return 0
}

func isProbeReachable(mode string, n *config.Node, res orchestrator.ProbeResult, hasRes bool) bool {
	if hasRes {
		if res.Error != "" {
			return false
		}
		switch normalizeProbeMode(mode) {
		case "ping":
			return res.PingMS > 0
		case "speed":
			return res.DownSpeedMbps > 0 || res.UpSpeedMbps > 0 || res.LatencyMS > 0
		case "full":
			return res.LatencyMS > 0 || res.DownSpeedMbps > 0 || res.PingMS > 0
		default:
			return res.LatencyMS > 0
		}
	}
	if n == nil {
		return false
	}
	return n.Latency > 0 || n.PingMS > 0 || n.DownSpeedMbps > 0
}

func groupPriorityBetter(aNode, bNode *config.Node, aRes, bRes orchestrator.ProbeResult, aHas, bHas bool, mode, rule string) bool {
	aOK := isProbeReachable(mode, aNode, aRes, aHas)
	bOK := isProbeReachable(mode, bNode, bRes, bHas)
	if aOK != bOK {
		return aOK
	}
	aLat := effectiveProbeLatency(aNode, aRes, aHas)
	bLat := effectiveProbeLatency(bNode, bRes, bHas)
	aDown := aNode.DownSpeedMbps
	bDown := bNode.DownSpeedMbps
	if aHas && aRes.DownSpeedMbps > 0 {
		aDown = aRes.DownSpeedMbps
	}
	if bHas && bRes.DownSpeedMbps > 0 {
		bDown = bRes.DownSpeedMbps
	}

	switch normalizePriorityRule(rule) {
	case "speed_first":
		if aDown != bDown {
			return aDown > bDown
		}
	case "hybrid_score":
		aEffLat := aLat
		if aEffLat <= 0 {
			aEffLat = 9999
		}
		bEffLat := bLat
		if bEffLat <= 0 {
			bEffLat = 9999
		}
		aScore := aDown*15.0 - float64(aEffLat)*0.25
		bScore := bDown*15.0 - float64(bEffLat)*0.25
		if aScore != bScore {
			return aScore > bScore
		}
	}

	aRank := aLat
	if aRank <= 0 {
		aRank = 1 << 30
	}
	bRank := bLat
	if bRank <= 0 {
		bRank = 1 << 30
	}
	if aRank != bRank {
		return aRank < bRank
	}
	return aDown > bDown
}

func (s *Server) probeAndReorderGroup(
	ctx context.Context,
	groupID string,
	mode string,
	priorityRule string,
	hs HealthSettings,
	forceSwitch bool,
) (*storage.Group, []orchestrator.ProbeResult, bool, error) {
	groups, err := s.store.ListGroups()
	if err != nil {
		return nil, nil, false, err
	}
	var target *storage.Group
	for i := range groups {
		if groups[i].ID == groupID {
			cp := groups[i]
			target = &cp
			break
		}
	}
	if target == nil {
		return nil, nil, false, os.ErrNotExist
	}

	normMode := normalizeProbeMode(mode)
	rule := hs.PriorityRule
	if strings.TrimSpace(target.PriorityRule) != "" {
		rule = normalizePriorityRule(target.PriorityRule)
	}
	if strings.TrimSpace(priorityRule) != "" {
		rule = normalizePriorityRule(priorityRule)
	}
	testURL := hs.URL
	if strings.TrimSpace(testURL) == "" {
		testURL = defaultProbeURL
	}

	memberNodes := make([]*config.Node, 0, len(target.NodeIDs))
	nodeByID := make(map[string]*config.Node, len(target.NodeIDs))
	for _, nid := range target.NodeIDs {
		if n := s.store.Get(nid); n != nil {
			memberNodes = append(memberNodes, n)
			nodeByID[nid] = n
		}
	}
	if len(memberNodes) == 0 {
		return target, []orchestrator.ProbeResult{}, false, nil
	}

	ordered, rawResults := s.probeNodesAndPersist(ctx, memberNodes, normMode, testURL, hs.SpeedDownURL, hs.SpeedUpURL, 10*time.Second)

	rankedIDs := append([]string(nil), target.NodeIDs...)
	sort.SliceStable(rankedIDs, func(i, j int) bool {
		idA, idB := rankedIDs[i], rankedIDs[j]
		rA, okA := rawResults[idA]
		rB, okB := rawResults[idB]
		return groupPriorityBetter(nodeByID[idA], nodeByID[idB], rA, rB, okA, okB, normMode, rule)
	})
	target.NodeIDs = rankedIDs

	switched := false
	bestID := rankedIDs[0]
	bestRes, hasBestRes := rawResults[bestID]
	bestReachable := isProbeReachable(normMode, nodeByID[bestID], bestRes, hasBestRes)

	allowAutoFailover := effectiveGroupAutoFailover(*target, hs.Failover)
	manualPinnedNoSwitch := storage.CanonicalGroupStrategy(target.Strategy) == "selector" &&
		target.AutoFailover != nil && !*target.AutoFailover && target.SelectedNodeID != ""
	canSwitchSelected := (forceSwitch && !manualPinnedNoSwitch) || (!forceSwitch && allowAutoFailover)

	if bestReachable && canSwitchSelected {
		prevSelected := target.SelectedNodeID
		if (forceSwitch && !manualPinnedNoSwitch) || prevSelected == "" {
			target.SelectedNodeID = bestID
		} else if prevSelected != bestID {
			prevRes, hasPrevRes := rawResults[prevSelected]
			prevReachable := isProbeReachable(normMode, nodeByID[prevSelected], prevRes, hasPrevRes)
			prevLat := effectiveProbeLatency(nodeByID[prevSelected], prevRes, hasPrevRes)
			bestLat := effectiveProbeLatency(nodeByID[bestID], bestRes, hasBestRes)
			tol := int64(target.ToleranceMS)
			if tol <= 0 {
				tol = int64(hs.ToleranceMS)
			}
			if tol <= 0 {
				tol = 50
			}
			if !prevReachable || (bestLat > 0 && prevLat-bestLat >= tol) {
				target.SelectedNodeID = bestID
			}
		}
		switched = target.SelectedNodeID != "" && target.SelectedNodeID != prevSelected
	}

	if err := s.store.SaveGroup(*target); err != nil {
		return nil, ordered, false, err
	}

	if s.ensureOrchestrator().Status().Running && (target.SelectedNodeID != "" || storage.CanonicalGroupStrategy(target.Strategy) == "loadbalance") {
		s.opMu.Lock()
		orch := s.ensureOrchestrator()
		if storage.CanonicalGroupStrategy(target.Strategy) == "selector" && target.SelectedNodeID != "" {
			_ = orch.HotSwitch(ctx, sbcfg.GroupTag(target.ID), sbcfg.NodeTag(target.SelectedNodeID))
		} else {
			_, _ = s.reconcileRuntime(ctx, s.activeNodeID, s.activeGroupID, s.tunEnabled)
		}
		s.opMu.Unlock()
	}

	return target, ordered, switched, nil
}

func effectiveGroupAutoFailover(g storage.Group, globalDefault bool) bool {
	if g.AutoFailover != nil {
		return *g.AutoFailover
	}
	if storage.CanonicalGroupStrategy(g.Strategy) == "selector" {
		return globalDefault
	}
	return true
}

func (s *Server) handleGroupProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	groupID := strings.TrimSpace(r.PathValue("id"))
	if groupID == "" {
		http.Error(w, "group id required", http.StatusBadRequest)
		return
	}
	var req struct {
		Mode         string `json:"mode,omitempty"`
		PriorityRule string `json:"priority_rule,omitempty"`
		URL          string `json:"url,omitempty"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	hs, _ := s.healthSettings()
	if strings.TrimSpace(req.URL) != "" {
		clean, err := validateHTTPSProbeURL(req.URL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		hs.URL = clean
	}
	group, results, switched, err := s.probeAndReorderGroup(r.Context(), groupID, req.Mode, req.PriorityRule, hs, true)
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	rule := hs.PriorityRule
	if group != nil && strings.TrimSpace(group.PriorityRule) != "" {
		rule = normalizePriorityRule(group.PriorityRule)
	}
	if strings.TrimSpace(req.PriorityRule) != "" {
		rule = normalizePriorityRule(req.PriorityRule)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"group":         group,
		"results":       results,
		"switched":      switched,
		"priority_rule": rule,
	})
}

func matchesNodeSearch(values []string, query string) bool {
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

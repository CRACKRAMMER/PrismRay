// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
	xc "github.com/CRACKRAMMER/PrismRay/backend/internal/xray/config"
)

// FullBackup represents an encrypted-at-rest exportable configuration snapshot (v4).
type FullBackup struct {
	Version        int                    `json:"version"`
	Nodes          []*config.Node         `json:"nodes"`
	Listeners      []*config.ListenConfig `json:"listeners"`
	Groups         []storage.Group        `json:"groups,omitempty"`
	Subscriptions  []Subscription         `json:"subscriptions,omitempty"`
	RoutingProfile ruleset.RoutingProfile `json:"routing_profile,omitempty"`
	RuleSets       []ruleset.RuleSetSpec  `json:"rule_sets,omitempty"`
	Preferences    *xc.Preferences        `json:"preferences,omitempty"`
	Health         *HealthSettings        `json:"health,omitempty"`
}

func validateFullBackup(b FullBackup) error {
	if b.Version != 3 && b.Version != 4 {
		return &httpError{Code: http.StatusBadRequest, Msg: "unsupported backup version (expected 3 or 4)"}
	}
	if b.Preferences != nil {
		if err := b.Preferences.Validate(); err != nil {
			return err
		}
	}
	if b.Health != nil && b.Health.URL != "" {
		if _, err := validateHTTPSProbeURL(b.Health.URL); err != nil {
			return err
		}
		if b.Health.IntervalSeconds != 0 && b.Health.IntervalSeconds < 30 {
			return &httpError{Code: http.StatusBadRequest, Msg: "health interval must be >= 30s"}
		}
	}
	return nil
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		includeRaw := strings.TrimSpace(r.URL.Query().Get("include"))
		includeAll := includeRaw == ""
		inc := map[string]bool{}
		if !includeAll {
			for _, part := range strings.Split(includeRaw, ",") {
				if key := strings.ToLower(strings.TrimSpace(part)); key != "" {
					inc[key] = true
				}
			}
			if len(inc) == 0 {
				includeAll = true
			}
		}
		want := func(keys ...string) bool {
			if includeAll {
				return true
			}
			for _, k := range keys {
				if inc[k] {
					return true
				}
			}
			return false
		}

		payload := FullBackup{Version: 4}
		if want("nodes") {
			payload.Nodes = s.store.List()
		}
		if want("listeners") {
			payload.Listeners = s.store.ListListeners()
		}
		if want("groups") {
			groups, err := s.store.ListGroups()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			payload.Groups = groups
		}
		if want("subscriptions", "subs") {
			subs, err := s.subscriptions()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			payload.Subscriptions = subs
		}
		if want("routing", "routing_profile", "dns") {
			routing, err := s.routingProfile()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ruleSets, err := s.effectiveRuleSets()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			payload.RoutingProfile = routing
			payload.RuleSets = ruleSets
		}
		if want("settings", "preferences", "health") {
			prefs, _ := s.preferences()
			health, _ := s.healthSettings()
			payload.Preferences = &prefs
			payload.Health = &health
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="prismray-backup-v4.json"`)
		_ = json.NewEncoder(w).Encode(payload)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("mode")), "merge") {
		s.handleMergeBackup(w, r)
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()
	if s.ensureOrchestrator().Status().Running {
		http.Error(w, "请先断开连接再恢复备份", http.StatusConflict)
		return
	}

	var b FullBackup
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateFullBackup(b); err != nil {
		respondError(w, err, http.StatusBadRequest)
		return
	}

	// Capture rollback snapshot before applying mutations.
	prevNodes := s.store.List()
	prevListeners := s.store.ListListeners()
	prevGroups, _ := s.store.ListGroups()
	prevSubs, _ := s.subscriptions()
	prevRouting, _ := s.routingProfile()

	rollback := func() {
		_ = s.store.Restore(prevNodes, prevListeners)
		_ = s.store.ReplaceGroups(prevGroups)
		for _, sub := range prevSubs {
			_ = s.store.SaveSubscription(sub)
		}
		_ = s.saveRoutingProfile(prevRouting)
	}

	if err := s.store.Restore(b.Nodes, b.Listeners); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.ReplaceGroups(b.Groups); err != nil {
		rollback()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, sub := range b.Subscriptions {
		if err := s.store.SaveSubscription(sub); err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if b.Version >= 4 {
		if err := s.saveRoutingProfile(b.RoutingProfile); err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, rs := range b.RuleSets {
			if strings.TrimSpace(rs.ID) == "" || strings.TrimSpace(rs.Tag) == "" {
				continue
			}
			cleanPath, pErr := sanitizeRuleSetPath(s.ruleSetDir(), rs.Tag, rs.LocalPath)
			if pErr != nil {
				cleanPath, pErr = sanitizeRuleSetPath(s.ruleSetDir(), rs.Tag, "")
				if pErr != nil {
					continue
				}
			}
			cleanURL := rs.URL
			if rs.SourceType == "remote" {
				if validatedURL, uErr := validateRuleSetURL(rs.URL); uErr == nil {
					cleanURL = validatedURL
				} else {
					continue
				}
			}
			_ = s.store.SaveRuleSet(storage.RuleSetRecord{
				ID:             strings.TrimSpace(rs.ID),
				Tag:            strings.TrimSpace(rs.Tag),
				Format:         rs.Format,
				SourceType:     rs.SourceType,
				URL:            cleanURL,
				LocalPath:      cleanPath,
				UpdateInterval: rs.UpdateInterval,
				Enabled:        rs.Enabled,
				LastSyncedAt:   rs.LastSyncedAt,
				SizeBytes:      rs.SizeBytes,
			})
		}
	}
	if b.Preferences != nil {
		_ = s.store.PutSetting("app.preferences", *b.Preferences)
		if b.Version == 3 {
			_ = s.saveRoutingProfile(syncRoutingFromPreferences(ruleset.DefaultRoutingProfile(), *b.Preferences))
		}
	}
	if b.Health != nil {
		_ = s.store.PutSetting("health.settings", *b.Health)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":          b.Version,
		"nodes":            len(b.Nodes),
		"listeners":        len(b.Listeners),
		"groups":           len(b.Groups),
		"subscriptions":    len(b.Subscriptions),
		"restart_required": false,
	})
}

func decodeMergePayload(raw []byte) (FullBackup, []byte, error) {
	var b FullBackup
	if err := json.Unmarshal(raw, &b); err != nil {
		return FullBackup{}, nil, err
	}
	if b.Version == 0 {
		b.Version = 4
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return FullBackup{}, nil, err
	}

	if rpRaw, ok := top["routing_profile"]; ok {
		trimmed := bytes.TrimSpace(rpRaw)
		if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
			return b, trimmed, nil
		}
	}

	// Support standalone RoutingProfile JSON files imported directly into the merge endpoint.
	for _, key := range []string{"custom_rules", "local_dns", "remote_dns"} {
		if _, ok := top[key]; ok {
			var standalone ruleset.RoutingProfile
			if err := json.Unmarshal(raw, &standalone); err != nil {
				return FullBackup{}, nil, err
			}
			b.RoutingProfile = standalone
			return b, raw, nil
		}
	}
	return b, nil, nil
}

func (s *Server) validateMergeBundle(b *FullBackup) error {
	if err := validateFullBackup(*b); err != nil {
		return err
	}

	knownNodes := map[string]bool{}
	for _, existing := range s.store.List() {
		if existing != nil && existing.ID != "" {
			knownNodes[existing.ID] = true
		}
	}
	for _, n := range b.Nodes {
		if n == nil {
			return &httpError{Code: http.StatusBadRequest, Msg: "invalid null node in merge bundle"}
		}
		if strings.TrimSpace(n.ID) == "" {
			n.ID = newRandomID("node-")
		}
		if err := n.Validate(); err != nil {
			return &httpError{Code: http.StatusBadRequest, Msg: err.Error()}
		}
		knownNodes[n.ID] = true
	}

	for _, l := range b.Listeners {
		if l == nil {
			return &httpError{Code: http.StatusBadRequest, Msg: "invalid null listener in merge bundle"}
		}
		if strings.TrimSpace(l.ID) == "" {
			l.ID = newRandomID("lis-")
		}
		if l.Port < 1 || l.Port > 65535 || l.Address == "" ||
			(l.Protocol != "http" && l.Protocol != "socks" && l.Protocol != "mixed") {
			return &httpError{Code: http.StatusBadRequest, Msg: fmt.Sprintf("invalid listener %q", l.ID)}
		}
		for _, nid := range l.NodeIDs {
			if !knownNodes[nid] {
				return &httpError{Code: http.StatusBadRequest, Msg: fmt.Sprintf("listener %q references missing node %q", l.ID, nid)}
			}
		}
	}

	for _, g := range b.Groups {
		if strings.TrimSpace(g.ID) == "" || strings.TrimSpace(g.Name) == "" {
			return &httpError{Code: http.StatusBadRequest, Msg: "group ID and name are required"}
		}
		switch g.Strategy {
		case "selector", "urltest", "failover", "manual", "latency":
		default:
			return &httpError{Code: http.StatusBadRequest, Msg: fmt.Sprintf("invalid group strategy %q", g.Strategy)}
		}
		for _, nid := range g.NodeIDs {
			if !knownNodes[nid] {
				return &httpError{Code: http.StatusBadRequest, Msg: fmt.Sprintf("group %q references missing node %q", g.ID, nid)}
			}
		}
	}
	return nil
}

func mergeRoutingProfile(existing ruleset.RoutingProfile, routingRaw []byte) (ruleset.RoutingProfile, error) {
	prevRules := existing.CustomRules
	merged := existing
	if existing.HijackDNS != nil {
		v := *existing.HijackDNS
		merged.HijackDNS = &v
	}
	if existing.KillSwitch != nil {
		v := *existing.KillSwitch
		merged.KillSwitch = &v
	}
	if len(existing.FakeIPFilter) > 0 {
		merged.FakeIPFilter = append([]string(nil), existing.FakeIPFilter...)
	}
	merged.CustomRules = nil
	if err := json.Unmarshal(routingRaw, &merged); err != nil {
		return ruleset.RoutingProfile{}, err
	}

	seenIDs := map[string]bool{}
	seenSignatures := map[string]bool{}
	for _, r := range merged.CustomRules {
		if id := strings.TrimSpace(r.ID); id != "" {
			seenIDs[id] = true
		}
		if sig, err := json.Marshal(r); err == nil {
			seenSignatures[string(sig)] = true
		}
	}
	for _, old := range prevRules {
		if id := strings.TrimSpace(old.ID); id != "" && seenIDs[id] {
			continue
		}
		if sig, err := json.Marshal(old); err == nil && seenSignatures[string(sig)] {
			continue
		}
		merged.CustomRules = append(merged.CustomRules, old)
	}
	merged.Normalize()
	return merged, nil
}

func (s *Server) handleMergeBackup(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b, routingRaw, err := decodeMergePayload(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	if err := s.validateMergeBundle(&b); err != nil {
		respondError(w, err, http.StatusBadRequest)
		return
	}

	for _, n := range b.Nodes {
		if s.store.Get(n.ID) != nil {
			if err := s.store.Update(n); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if err := s.store.Add(n); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	existingListeners := map[string]bool{}
	for _, l := range s.store.ListListeners() {
		if l != nil && l.ID != "" {
			existingListeners[l.ID] = true
		}
	}
	for _, l := range b.Listeners {
		if existingListeners[l.ID] {
			if err := s.store.UpdateListener(l); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if err := s.store.AddListener(l); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	for _, g := range b.Groups {
		if err := s.store.SaveGroup(g); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	for _, sub := range b.Subscriptions {
		if err := s.store.SaveSubscription(sub); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	for _, rs := range b.RuleSets {
		if rs.ID == "" || rs.Tag == "" {
			continue
		}
		_ = s.store.SaveRuleSet(storage.RuleSetRecord{
			ID:             rs.ID,
			Tag:            rs.Tag,
			Format:         rs.Format,
			SourceType:     rs.SourceType,
			URL:            rs.URL,
			LocalPath:      rs.LocalPath,
			UpdateInterval: rs.UpdateInterval,
			Enabled:        rs.Enabled,
			LastSyncedAt:   rs.LastSyncedAt,
			SizeBytes:      rs.SizeBytes,
		})
	}

	customCount := 0
	if len(routingRaw) > 0 {
		cur, _ := s.routingProfile()
		merged, err := mergeRoutingProfile(cur, routingRaw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.saveRoutingProfile(merged); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		customCount = len(merged.CustomRules)
	} else {
		cur, _ := s.routingProfile()
		customCount = len(cur.CustomRules)
	}

	if b.Preferences != nil {
		_ = s.store.PutSetting("app.preferences", *b.Preferences)
	}
	if b.Health != nil {
		_ = s.store.PutSetting("health.settings", *b.Health)
	}

	if s.ensureOrchestrator().Status().Running {
		if _, err := s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled); err != nil {
			respondError(w, err, http.StatusBadGateway)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"mode":             "merge",
		"version":          b.Version,
		"nodes":            len(b.Nodes),
		"groups":           len(b.Groups),
		"custom_rules":     customCount,
		"restart_required": false,
	})
}

// RecoverBackup cleans or completes interrupted SQLite backup marker files before opening the database.
func RecoverBackup(cfg *appconfig.Config) error {
	if cfg == nil {
		return nil
	}
	dir := cfg.DataDir()
	if dir == "" {
		return nil
	}
	backupMarker := filepath.Join(dir, "prismray.db.bak")
	if _, err := os.Stat(backupMarker); err == nil {
		_ = os.Remove(backupMarker)
	}
	return nil
}

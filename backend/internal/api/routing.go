// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func sanitizeRuleSetPath(baseDir, tagOrID, rawPath string) (string, error) {
	absBase, err := filepath.Abs(strings.TrimSpace(baseDir))
	if err != nil {
		return "", fmt.Errorf("invalid rule set directory: %w", err)
	}
	absBase = filepath.Clean(absBase)

	candidate := strings.TrimSpace(rawPath)
	if candidate == "" {
		safeName := strings.TrimSpace(tagOrID)
		safeName = strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(safeName)
		if safeName == "" || safeName == "." {
			return "", fmt.Errorf("invalid rule set tag/id")
		}
		if !strings.HasSuffix(safeName, ".srs") && !strings.HasSuffix(safeName, ".json") {
			safeName += ".srs"
		}
		candidate = filepath.Join(absBase, safeName)
	} else if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(absBase, candidate)
	}

	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("invalid rule set path: %w", err)
	}
	absCandidate = filepath.Clean(absCandidate)
	rel, err := filepath.Rel(absBase, absCandidate)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("rule set local_path must stay inside %s", absBase)
	}
	return absCandidate, nil
}

func validateRuleSetURL(rawURL string) (string, error) {
	u, err := url.ParseRequestURI(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("rule set URL must be a valid http(s) URL")
	}
	return u.String(), nil
}

func (s *Server) handleRouting(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		profile, err := s.routingProfile()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, profile)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var profile ruleset.RoutingProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch strings.TrimSpace(profile.Mode) {
	case "", "rule", "global", "direct":
	default:
		http.Error(w, "routing mode must be rule, global, or direct", http.StatusBadRequest)
		return
	}
	if profile.PerAppMode != "" && profile.PerAppMode != "all" && profile.PerAppMode != "whitelist" && profile.PerAppMode != "blacklist" {
		http.Error(w, "per_app_mode must be all, whitelist, or blacklist", http.StatusBadRequest)
		return
	}
	prev, _ := s.routingProfile()
	if err := s.saveRoutingProfile(profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	profile, _ = s.routingProfile()

	s.opMu.Lock()
	running := s.ensureOrchestrator().Status().Running
	var applyErr error
	if running {
		_, applyErr = s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled)
		if applyErr != nil {
			_ = s.saveRoutingProfile(prev)
		}
	}
	s.opMu.Unlock()

	if applyErr != nil {
		respondError(w, applyErr, http.StatusBadGateway)
		return
	}
	if !profile.KillSwitchEnabled() || profile.Mode == "direct" {
		if tripped, _, intended := s.killSwitchSnapshot(); tripped {
			if intended != "" {
				_ = s.ensureOrchestrator().HotSwitch(r.Context(), "proxy", intended)
			}
			s.clearKillSwitch()
		}
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Server) handleRoutingSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in ruleset.SimulationInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	profile, err := s.routingProfile()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	res := ruleset.Simulate(profile, in)
	if strings.TrimSpace(in.Domain) != "" && res.Action == "route" && res.Outbound != "direct" {
		if groups, gErr := s.store.ListGroups(); gErr == nil {
			targetGroupID := res.Outbound
			if targetGroupID == "proxy" {
				s.opMu.Lock()
				targetGroupID = s.activeGroupID
				s.opMu.Unlock()
			}
			for _, g := range groups {
				if g.ID == targetGroupID && storage.CanonicalGroupStrategy(g.Strategy) == "loadbalance" {
					var healthyIDs []string
					for _, nid := range g.NodeIDs {
						if n := s.store.Get(nid); n != nil && n.Latency >= 0 {
							healthyIDs = append(healthyIDs, nid)
						}
					}
					if len(healthyIDs) == 0 {
						healthyIDs = append(healthyIDs, g.NodeIDs...)
					}
					if len(healthyIDs) > 8 {
						healthyIDs = healthyIDs[:8]
					}
					if idx := sbcfg.DomainHashShardIndex(in.Domain, len(healthyIDs)); idx >= 0 && idx < len(healthyIDs) {
						label := healthyIDs[idx]
						if n := s.store.Get(healthyIDs[idx]); n != nil {
							label = n.Name
							if strings.TrimSpace(n.UserAlias) != "" {
								label = n.UserAlias
							}
						}
						res.MatchedRule = fmt.Sprintf("%s -> shard#%d (%s)", res.MatchedRule, idx+1, label)
					}
					break
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleRuleSets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		specs, err := s.effectiveRuleSets()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, specs)
	case http.MethodPost:
		var spec ruleset.RuleSetSpec
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(spec.ID) == "" {
			spec.ID = strings.TrimSpace(spec.Tag)
		}
		spec.ID = strings.TrimSpace(spec.ID)
		spec.Tag = strings.TrimSpace(spec.Tag)
		if spec.Tag == "" || spec.ID == "" {
			http.Error(w, "id and tag are required", http.StatusBadRequest)
			return
		}
		if strings.ContainsAny(spec.Tag, "/\\") || strings.Contains(spec.Tag, "..") || strings.ContainsAny(spec.ID, "/\\") || strings.Contains(spec.ID, "..") {
			http.Error(w, "id and tag cannot contain path separators or '..'", http.StatusBadRequest)
			return
		}
		spec.SourceType = strings.TrimSpace(spec.SourceType)
		if spec.SourceType == "" {
			spec.SourceType = "remote"
		}
		switch spec.SourceType {
		case "remote":
			cleanURL, uErr := validateRuleSetURL(spec.URL)
			if uErr != nil {
				http.Error(w, uErr.Error(), http.StatusBadRequest)
				return
			}
			spec.URL = cleanURL
			cleanPath, pErr := sanitizeRuleSetPath(s.ruleSetDir(), spec.Tag, spec.LocalPath)
			if pErr != nil {
				http.Error(w, pErr.Error(), http.StatusBadRequest)
				return
			}
			spec.LocalPath = cleanPath
		case "local":
			cleanPath, pErr := sanitizeRuleSetPath(s.ruleSetDir(), spec.Tag, spec.LocalPath)
			if pErr != nil {
				http.Error(w, pErr.Error(), http.StatusBadRequest)
				return
			}
			spec.LocalPath = cleanPath
		case "inline":
			spec.LocalPath = ""
		default:
			http.Error(w, "source_type must be remote, local, or inline", http.StatusBadRequest)
			return
		}
		if err := s.store.SaveRuleSet(storage.RuleSetRecord{
			ID:             spec.ID,
			Tag:            spec.Tag,
			Format:         spec.Format,
			SourceType:     spec.SourceType,
			URL:            spec.URL,
			LocalPath:      spec.LocalPath,
			UpdateInterval: spec.UpdateInterval,
			Enabled:        spec.Enabled,
			LastSyncedAt:   spec.LastSyncedAt,
			SizeBytes:      spec.SizeBytes,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		specs, err := s.effectiveRuleSets()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, specs)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSyncRuleSets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs []string `json:"ids,omitempty"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	wantIDs := map[string]bool{}
	for _, id := range req.IDs {
		wantIDs[id] = true
	}

	specs, err := s.effectiveRuleSets()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	client := safeHTTPClient(30 * time.Second)
	results := make([]ruleset.RuleSetSpec, 0, len(specs))
	errs := map[string]string{}
	for _, spec := range specs {
		if !spec.Enabled && !wantIDs[spec.ID] {
			results = append(results, spec)
			continue
		}
		if len(wantIDs) > 0 && !wantIDs[spec.ID] {
			results = append(results, spec)
			continue
		}
		if spec.SourceType != "remote" {
			results = append(results, spec)
			continue
		}
		cleanURL, uErr := validateRuleSetURL(spec.URL)
		if uErr != nil {
			errs[spec.ID] = uErr.Error()
			results = append(results, spec)
			continue
		}
		cleanPath, pErr := sanitizeRuleSetPath(s.ruleSetDir(), spec.Tag, spec.LocalPath)
		if pErr != nil {
			errs[spec.ID] = pErr.Error()
			results = append(results, spec)
			continue
		}
		spec.URL = cleanURL
		spec.LocalPath = cleanPath
		synced, syncErr := ruleset.SyncRuleSet(r.Context(), client, spec)
		if syncErr != nil {
			errs[spec.ID] = syncErr.Error()
			results = append(results, spec)
			continue
		}
		_ = s.store.SaveRuleSet(storage.RuleSetRecord{
			ID:             synced.ID,
			Tag:            synced.Tag,
			Format:         synced.Format,
			SourceType:     synced.SourceType,
			URL:            synced.URL,
			LocalPath:      synced.LocalPath,
			UpdateInterval: synced.UpdateInterval,
			Enabled:        synced.Enabled,
			LastSyncedAt:   synced.LastSyncedAt,
			SizeBytes:      synced.SizeBytes,
		})
		results = append(results, synced)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"rule_sets": results,
		"errors":    errs,
	})
}

// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
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
	s.opMu.Lock()
	prev, _ := s.routingProfile()
	if err := s.saveRoutingProfile(profile); err != nil {
		s.opMu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	profile, _ = s.routingProfile()

	running := s.ensureOrchestrator().Status().Running
	var applyErr error
	if running {
		rs := s.runtimeState()
		_, applyErr = s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, rs.tunEnabled)
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
				targetGroupID = s.runtimeState().activeGroupID
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
					shardLimit := sbcfg.EffectiveLoadBalanceShards(g)
					if len(healthyIDs) > shardLimit {
						healthyIDs = healthyIDs[:shardLimit]
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
		if deleted := s.deletedBuiltinRuleSetIDs(); deleted[spec.ID] {
			delete(deleted, spec.ID)
			_ = s.setDeletedBuiltinRuleSetIDs(deleted)
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

func safeProxyHTTPClient(timeout time.Duration, proxyPort int) *http.Client {
	return safeProxyHTTPClientWithPolicy(timeout, proxyPort, false)
}

func (s *Server) syncRuleSetsInternal(ctx context.Context, wantIDs map[string]bool) ([]ruleset.RuleSetSpec, map[string]string, int, bool, error) {
	s.ruleSetSyncMu.Lock()
	defer s.ruleSetSyncMu.Unlock()

	specs, err := s.effectiveRuleSets()
	if err != nil {
		return nil, nil, 0, false, err
	}

	// Build resilient sync pipeline:
	// 1. Local proxy (if core is currently running) — bypasses GitHub Raw throttling/blocking on mobile/CN networks.
	// 2. Direct connection — works when proxy is stopped or local network reaches GitHub directly.
	// 3. Built-in CDN mirrors (e.g. jsDelivr for raw.githubusercontent.com) via direct/proxy.
	allowLAN := s.allowLANSubscriptionFetch()
	orchStatus := s.ensureOrchestrator().Status()
	var proxyClient *http.Client
	if orchStatus.Running && orchStatus.MixedPort > 0 {
		proxyClient = s.safeProxyHTTPClient(15*time.Second, orchStatus.MixedPort)
		defer closeClientIdleConnections(proxyClient)
	}
	directClient := s.safeHTTPClient(15 * time.Second)
	defer closeClientIdleConnections(directClient)

	syncWithFallback := func(spec ruleset.RuleSetSpec) (ruleset.RuleSetSpec, error) {
		canonicalURL := spec.URL
		if err := validateFetchTargetURL(ctx, canonicalURL, allowLAN); err != nil {
			return spec, err
		}
		type attempt struct {
			client *http.Client
			url    string
		}
		var attempts []attempt
		if proxyClient != nil {
			attempts = append(attempts, attempt{client: proxyClient, url: canonicalURL})
		}
		attempts = append(attempts, attempt{client: directClient, url: canonicalURL})
		for _, mirror := range ruleset.MirrorURLs(canonicalURL) {
			if validateFetchTargetURL(ctx, mirror, allowLAN) != nil {
				continue
			}
			attempts = append(attempts, attempt{client: directClient, url: mirror})
			if proxyClient != nil {
				attempts = append(attempts, attempt{client: proxyClient, url: mirror})
			}
		}

		var lastErr error
		for _, a := range attempts {
			trySpec := spec
			trySpec.URL = a.url
			synced, syncErr := ruleset.SyncRuleSet(ctx, a.client, trySpec)
			if syncErr == nil {
				// Preserve canonical source URL in persisted metadata.
				synced.URL = canonicalURL
				return synced, nil
			}
			if errors.Is(syncErr, errSSRFBlocked) {
				return spec, syncErr
			}
			lastErr = syncErr
		}
		return spec, lastErr
	}

	results := make([]ruleset.RuleSetSpec, 0, len(specs))
	errs := map[string]string{}
	syncedCount := 0
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
		synced, syncErr := syncWithFallback(spec)
		if syncErr != nil {
			errs[spec.ID] = syncErr.Error()
			results = append(results, spec)
			continue
		}
		syncedCount++
		if s.store != nil {
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
		}
		results = append(results, synced)
	}

	// Automatically hot-reload sing-box when any .srs rule set was synced while running,
	// so newly downloaded local .srs binaries take effect immediately without manual restart.
	reloaded := false
	if syncedCount > 0 {
		s.opMu.Lock()
		if s.ensureOrchestrator().Status().Running {
			rs := s.runtimeState()
			if _, recErr := s.reconcileRuntime(ctx, rs.activeNodeID, rs.activeGroupID, rs.tunEnabled); recErr == nil {
				reloaded = true
			} else {
				s.ensureOrchestrator().AppendLog("system", "warn", "规则集同步后热重载失败: "+recErr.Error())
			}
		}
		s.opMu.Unlock()
	}
	return results, errs, syncedCount, reloaded, nil
}

// maybeAutoSyncRuleSetsAsync silently downloads missing built-in .srs files once after the first
// successful proxy connection so BlockAds / BypassCN switches unlock automatically without blocking connect.
func (s *Server) maybeAutoSyncRuleSetsAsync() {
	if s.store == nil || !s.autoSyncedRuleSets.CompareAndSwap(false, true) {
		return
	}
	specs, err := s.effectiveRuleSets()
	if err != nil {
		return
	}
	missing := map[string]bool{}
	for _, spec := range specs {
		if spec.Enabled && spec.SourceType == "remote" && !spec.Synced {
			missing[spec.ID] = true
		}
	}
	if len(missing) == 0 {
		return
	}
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		// Brief delay so newly started sing-box finishes settling before fetching via local mixed port.
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-bgCtx.Done():
			return
		}
		_, errs, syncedCount, reloaded, syncErr := s.syncRuleSetsInternal(bgCtx, missing)
		if syncErr != nil {
			s.ensureOrchestrator().AppendLog("system", "warn", "首次连接后台自动同步 .srs 规则集失败: "+syncErr.Error())
			return
		}
		if syncedCount > 0 {
			s.ensureOrchestrator().AppendLog("system", "info", fmt.Sprintf("首次连接已自动同步 %d 个 .srs 规则集 (热重载=%v)", syncedCount, reloaded))
		} else if len(errs) > 0 {
			s.ensureOrchestrator().AppendLog("system", "warn", fmt.Sprintf("后台自动同步 .srs 未完成 (%d 项失败)，可在路由页手动同步", len(errs)))
		}
	}()
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

	results, errs, syncedCount, reloaded, err := s.syncRuleSetsInternal(r.Context(), wantIDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"rule_sets":    results,
		"errors":       errs,
		"synced_count": syncedCount,
		"reloaded":     reloaded,
	})
}

func (s *Server) handleDeleteRuleSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "rule set id is required", http.StatusBadRequest)
		return
	}
	specs, err := s.effectiveRuleSets()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var target *ruleset.RuleSetSpec
	for i := range specs {
		if specs[i].ID == id {
			cp := specs[i]
			target = &cp
			break
		}
	}
	if target == nil {
		http.Error(w, "rule set not found", http.StatusNotFound)
		return
	}
	if strings.HasPrefix(id, "builtin-") {
		deleted := s.deletedBuiltinRuleSetIDs()
		deleted[id] = true
		if err := s.setDeletedBuiltinRuleSetIDs(deleted); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.store.DeleteRuleSet(id); err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := s.store.DeleteRuleSet(id); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "rule set not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if target.LocalPath != "" {
		if safePath, pErr := sanitizeRuleSetPath(s.ruleSetDir(), target.Tag, target.LocalPath); pErr == nil {
			_ = os.Remove(safePath)
		}
	}
	s.opMu.Lock()
	if s.ensureOrchestrator().Status().Running {
		rs := s.runtimeState()
		_, _ = s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, rs.tunEnabled)
	}
	s.opMu.Unlock()

	updated, err := s.effectiveRuleSets()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleRestoreBuiltinRuleSets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.setDeletedBuiltinRuleSetIDs(nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.opMu.Lock()
	if s.ensureOrchestrator().Status().Running {
		rs := s.runtimeState()
		_, _ = s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, rs.tunEnabled)
	}
	s.opMu.Unlock()

	updated, err := s.effectiveRuleSets()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func parseRuleSetUpdateInterval(raw string) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || d <= 0 {
		return 24 * time.Hour
	}
	if d < time.Hour {
		return time.Hour
	}
	if d > 30*24*time.Hour {
		return 30 * 24 * time.Hour
	}
	return d
}

// maintainRuleSets periodically refreshes stale enabled remote .srs rule sets according to their update_interval.
func (s *Server) maintainRuleSets(ctx context.Context) {
	if s.store == nil {
		return
	}
	s.stateMu.Lock()
	if !s.lastRuleSetCheck.IsZero() && time.Since(s.lastRuleSetCheck) < 10*time.Minute {
		s.stateMu.Unlock()
		return
	}
	s.lastRuleSetCheck = time.Now()
	s.stateMu.Unlock()

	specs, err := s.effectiveRuleSets()
	if err != nil {
		return
	}
	now := time.Now().UTC()
	dueIDs := map[string]bool{}
	for _, spec := range specs {
		if !spec.Enabled || spec.SourceType != "remote" {
			continue
		}
		interval := parseRuleSetUpdateInterval(spec.UpdateInterval)
		if !spec.Synced || strings.TrimSpace(spec.LastSyncedAt) == "" {
			if s.ensureOrchestrator().Status().Running {
				dueIDs[spec.ID] = true
			}
			continue
		}
		lastSynced, pErr := time.Parse(time.RFC3339, spec.LastSyncedAt)
		if pErr != nil || now.Sub(lastSynced) >= interval {
			dueIDs[spec.ID] = true
		}
	}
	if len(dueIDs) == 0 {
		return
	}
	syncCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	_, _, syncedCount, reloaded, syncErr := s.syncRuleSetsInternal(syncCtx, dueIDs)
	if syncErr == nil && syncedCount > 0 {
		s.ensureOrchestrator().AppendLog("system", "info", fmt.Sprintf("后台定时更新了 %d 个 .srs 规则集 (热重载=%v)", syncedCount, reloaded))
	}
}

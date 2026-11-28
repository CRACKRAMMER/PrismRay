// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func nodeContentFingerprint(n *config.Node) string {
	if n == nil {
		return ""
	}
	parts := []string{
		strings.ToLower(strings.TrimSpace(string(n.Protocol))),
		strings.ToLower(strings.TrimSpace(n.Address)),
		fmt.Sprintf("%d", n.Port),
		strings.TrimSpace(n.UUID),
		strings.TrimSpace(n.Password),
		strings.ToLower(strings.TrimSpace(n.Method)),
		strings.ToLower(strings.TrimSpace(n.Security)),
		strings.ToLower(strings.TrimSpace(n.Sni)),
		strings.ToLower(strings.TrimSpace(n.Host)),
		strings.TrimSpace(n.Path),
		strings.ToLower(strings.TrimSpace(n.Network)),
		strings.TrimSpace(n.PublicKey),
		strings.TrimSpace(n.ShortID),
		strings.TrimSpace(n.PrivateKey),
		strings.TrimSpace(n.ServiceName),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:6])
}

func (s *Server) recordSubscriptionRefreshResult(subID string, err error) {
	s.subBackoffMu.Lock()
	defer s.subBackoffMu.Unlock()
	if s.subBackoff == nil {
		s.subBackoff = map[string]subRetryState{}
	}
	if err == nil {
		delete(s.subBackoff, subID)
		return
	}
	st := s.subBackoff[subID]
	st.failures++
	delay := 5 * time.Minute
	switch {
	case st.failures == 1:
		delay = 5 * time.Minute
	case st.failures == 2:
		delay = 15 * time.Minute
	case st.failures == 3:
		delay = 1 * time.Hour
	default:
		delay = 6 * time.Hour
	}
	st.nextRetryAt = time.Now().Add(delay)
	s.subBackoff[subID] = st
}

func (s *Server) shouldSkipSubscriptionAutoUpdate(subID string, now time.Time) bool {
	s.subBackoffMu.Lock()
	defer s.subBackoffMu.Unlock()
	if st, ok := s.subBackoff[subID]; ok && now.Before(st.nextRetryAt) {
		return true
	}
	return false
}

func assignDeterministicSubscriptionNodeIDs(subID string, nodes []*config.Node) {
	seenCount := make(map[string]int, len(nodes))
	for _, n := range nodes {
		n.SubID = subID
		if strings.TrimSpace(n.ID) != "" {
			continue
		}
		fp := nodeContentFingerprint(n)
		seenCount[fp]++
		if seenCount[fp] == 1 {
			n.ID = fmt.Sprintf("%s-%s", subID, fp)
		} else {
			n.ID = fmt.Sprintf("%s-%s-%d", subID, fp, seenCount[fp])
		}
	}
}

type Subscription = storage.SubscriptionRecord

// SubscriptionDiff summarizes node additions, removals, and renames detected on refresh.
type SubscriptionDiff struct {
	Added        int      `json:"added"`
	Removed      int      `json:"removed"`
	Renamed      int      `json:"renamed"`
	FilteredOut  int      `json:"filtered_out,omitempty"`
	AddedNames   []string `json:"added_names,omitempty"`
	RemovedNames []string `json:"removed_names,omitempty"`
}

// SubscriptionRefreshResponse embeds Subscription fields with structured refresh diff telemetry.
type SubscriptionRefreshResponse struct {
	Subscription
	Diff *SubscriptionDiff `json:"diff,omitempty"`
}

func validateSubscriptionRegex(pattern string) error {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return nil
	}
	if len(p) > 256 {
		return fmt.Errorf("regex pattern too long (max 256 chars)")
	}
	if _, err := regexp.Compile(p); err != nil {
		return fmt.Errorf("invalid regex %q: %w", p, err)
	}
	return nil
}

func filterSubscriptionNodes(nodes []*config.Node, includePattern, excludePattern string) ([]*config.Node, int, error) {
	var incRe, excRe *regexp.Regexp
	var err error
	if p := strings.TrimSpace(includePattern); p != "" {
		incRe, err = regexp.Compile(p)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid include_regex: %w", err)
		}
	}
	if p := strings.TrimSpace(excludePattern); p != "" {
		excRe, err = regexp.Compile(p)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid exclude_regex: %w", err)
		}
	}
	if incRe == nil && excRe == nil {
		return nodes, 0, nil
	}
	kept := make([]*config.Node, 0, len(nodes))
	filtered := 0
	for _, n := range nodes {
		if n == nil {
			continue
		}
		target := n.Name
		if incRe != nil && !incRe.MatchString(target) {
			filtered++
			continue
		}
		if excRe != nil && excRe.MatchString(target) {
			filtered++
			continue
		}
		kept = append(kept, n)
	}
	return kept, filtered, nil
}

func computeSubscriptionDiff(prevNodes, nextNodes []*config.Node, filteredOut int) SubscriptionDiff {
	diff := SubscriptionDiff{FilteredOut: filteredOut}
	prevByID := make(map[string]*config.Node, len(prevNodes))
	nextByID := make(map[string]*config.Node, len(nextNodes))
	for _, n := range prevNodes {
		if n != nil && n.ID != "" {
			prevByID[n.ID] = n
		}
	}
	for _, n := range nextNodes {
		if n != nil && n.ID != "" {
			nextByID[n.ID] = n
		}
	}

	const maxNames = 20
	for id, next := range nextByID {
		prev, existed := prevByID[id]
		if !existed {
			diff.Added++
			if len(diff.AddedNames) < maxNames && strings.TrimSpace(next.Name) != "" {
				diff.AddedNames = append(diff.AddedNames, next.Name)
			}
		} else if prev.Name != next.Name {
			diff.Renamed++
		}
	}
	for id, prev := range prevByID {
		if _, exists := nextByID[id]; !exists {
			diff.Removed++
			if len(diff.RemovedNames) < maxNames && strings.TrimSpace(prev.Name) != "" {
				diff.RemovedNames = append(diff.RemovedNames, prev.Name)
			}
		}
	}
	return diff
}

func (s *Server) subscriptions() ([]Subscription, error) {
	if s.store == nil {
		return []Subscription{}, nil
	}
	return s.store.ListSubscriptions()
}

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := s.subscriptions()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}

	if r.Method == http.MethodDelete {
		id := strings.TrimSpace(r.PathValue("id"))
		if id == "" {
			http.Error(w, "subscription id required", http.StatusBadRequest)
			return
		}
		_ = s.store.SyncSubscriptionNodes(id, nil)
		err := s.store.DeleteSubscription(id)
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "subscription not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		list, err := s.subscriptions()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		URL             string `json:"url"`
		IncludeRegex    string `json:"include_regex"`
		ExcludeRegex    string `json:"exclude_regex"`
		AutoUpdateHours int    `json:"auto_update_hours"`
		IntervalMinutes int    `json:"interval_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := url.ParseRequestURI(strings.TrimSpace(req.URL))
	if strings.TrimSpace(req.Name) == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "需要名称与有效的 HTTP(S) 订阅地址", http.StatusBadRequest)
		return
	}
	if err := validateSubscriptionRegex(req.IncludeRegex); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateSubscriptionRegex(req.ExcludeRegex); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hours := req.AutoUpdateHours
	if hours <= 0 && req.IntervalMinutes > 0 {
		if req.IntervalMinutes < 5 {
			http.Error(w, "自动更新间隔不能小于 5 分钟", http.StatusBadRequest)
			return
		}
		hours = max(1, req.IntervalMinutes/60)
	}
	if hours < 0 {
		http.Error(w, "auto_update_hours cannot be negative", http.StatusBadRequest)
		return
	}

	sub := Subscription{
		ID:              strings.TrimSpace(req.ID),
		Name:            strings.TrimSpace(req.Name),
		URL:             u.String(),
		IncludeRegex:    strings.TrimSpace(req.IncludeRegex),
		ExcludeRegex:    strings.TrimSpace(req.ExcludeRegex),
		AutoUpdateHours: hours,
		Warnings:        []string{},
	}
	if sub.ID == "" {
		sub.ID = newRandomID("sub-")
	}
	if err := s.store.SaveSubscription(sub); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	list, err := s.subscriptions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "subscription id required", http.StatusBadRequest)
		return
	}
	existing, found, err := s.store.GetSubscription(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "subscription not found", http.StatusNotFound)
		return
	}
	var req struct {
		Name            string  `json:"name"`
		URL             string  `json:"url"`
		IncludeRegex    *string `json:"include_regex"`
		ExcludeRegex    *string `json:"exclude_regex"`
		AutoUpdateHours *int    `json:"auto_update_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		existing.Name = strings.TrimSpace(req.Name)
	}
	if strings.TrimSpace(req.URL) != "" {
		u, err := url.ParseRequestURI(strings.TrimSpace(req.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			http.Error(w, "需要有效的 HTTP(S) 订阅地址", http.StatusBadRequest)
			return
		}
		existing.URL = u.String()
	}
	if req.IncludeRegex != nil {
		if err := validateSubscriptionRegex(*req.IncludeRegex); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		existing.IncludeRegex = strings.TrimSpace(*req.IncludeRegex)
	}
	if req.ExcludeRegex != nil {
		if err := validateSubscriptionRegex(*req.ExcludeRegex); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		existing.ExcludeRegex = strings.TrimSpace(*req.ExcludeRegex)
	}
	if req.AutoUpdateHours != nil {
		if *req.AutoUpdateHours < 0 {
			http.Error(w, "auto_update_hours cannot be negative", http.StatusBadRequest)
			return
		}
		existing.AutoUpdateHours = *req.AutoUpdateHours
	}
	if err := s.store.SaveSubscription(*existing); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, existing)
}

func (s *Server) refreshSubscription(ctx context.Context, v *Subscription) error {
	_, err := s.refreshSubscriptionWithDiff(ctx, v, true)
	return err
}

func (s *Server) refreshSubscriptionWithDiff(ctx context.Context, v *Subscription, reconcileNow bool) (*SubscriptionDiff, error) {
	if v == nil || strings.TrimSpace(v.URL) == "" {
		return nil, fmt.Errorf("subscription url is required")
	}
	if strings.TrimSpace(v.ID) == "" {
		v.ID = newRandomID("sub-")
	}

	allowLAN := s.allowLANSubscriptionFetch()
	if err := validateFetchTargetURL(ctx, v.URL, allowLAN); err != nil {
		return nil, err
	}

	client := s.safeHTTPClient(20 * time.Second)
	defer closeClientIdleConnections(client)
	doFetch := func(c *http.Client) (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, v.URL, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("User-Agent", "PrismRay/1.0.1")
		return c.Do(req)
	}
	resp, err := doFetch(client)
	if err != nil && !errors.Is(err, errSSRFBlocked) {
		// If direct fetch failed for non-SSRF reasons and the proxy core is running locally,
		// retry via the local mixed port with redirect SSRF validation preserved.
		if st := s.ensureOrchestrator().Status(); st.Running && st.MixedPort > 0 {
			proxied := s.safeProxyHTTPClient(20*time.Second, st.MixedPort)
			defer closeClientIdleConnections(proxied)
			if pResp, pErr := doFetch(proxied); pErr == nil {
				resp, err = pResp, nil
			} else if errors.Is(pErr, errSSRFBlocked) {
				err = pErr
			}
		}
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	meta := config.ParseUserinfoHeader(resp.Header.Get("Subscription-Userinfo"))
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	res, err := config.ParseSubscriptionResilient(string(body))
	if err != nil {
		return nil, err
	}
	if len(res.Nodes) == 0 {
		if len(res.Skipped) > 0 {
			return nil, fmt.Errorf("subscription produced 0 valid nodes (%s)", res.Skipped[0].Reason)
		}
		return nil, fmt.Errorf("subscription produced 0 valid nodes")
	}

	filteredNodes, filteredOut, err := filterSubscriptionNodes(res.Nodes, v.IncludeRegex, v.ExcludeRegex)
	if err != nil {
		return nil, err
	}
	if len(filteredNodes) == 0 {
		return nil, fmt.Errorf("all %d nodes were filtered out by include/exclude regex", len(res.Nodes))
	}

	if res.Meta.TotalBytes > 0 || res.Meta.UploadBytes > 0 || res.Meta.DownloadBytes > 0 || res.Meta.ExpireUnix > 0 {
		if meta.TotalBytes == 0 {
			meta.TotalBytes = res.Meta.TotalBytes
		}
		if meta.UploadBytes == 0 {
			meta.UploadBytes = res.Meta.UploadBytes
		}
		if meta.DownloadBytes == 0 {
			meta.DownloadBytes = res.Meta.DownloadBytes
		}
		if meta.ExpireUnix == 0 {
			meta.ExpireUnix = res.Meta.ExpireUnix
		}
	}

	// Assign deterministic content-hash node IDs so insertions/deletions in a provider feed never
	// shift subsequent IDs and corrupt aliases, favorites, tags, groups, or active selections.
	assignDeterministicSubscriptionNodeIDs(v.ID, filteredNodes)

	prevNodes := s.store.ListBySubscription(v.ID)
	prevGroups, prevGroupsErr := s.store.ListGroups()
	prevListeners := s.store.ListListeners()
	prevTS, prevTSErr := s.tailscaleConfig(false)
	// Migrate persisted user metadata and references from legacy positional (<subID>-<idx>) IDs
	// to their new deterministic content-hash IDs seamlessly on upgrade.
	prevByID := make(map[string]*config.Node, len(prevNodes))
	prevByFP := make(map[string][]*config.Node, len(prevNodes))
	for _, pn := range prevNodes {
		if pn == nil {
			continue
		}
		prevByID[pn.ID] = pn
		fp := nodeContentFingerprint(pn)
		prevByFP[fp] = append(prevByFP[fp], pn)
	}
	migratedIDMap := map[string]string{}
	for _, n := range filteredNodes {
		if _, exact := prevByID[n.ID]; exact {
			continue
		}
		fp := nodeContentFingerprint(n)
		cands := prevByFP[fp]
		if len(cands) > 0 {
			prev := cands[0]
			prevByFP[fp] = cands[1:]
			if prev.ID != n.ID {
				migratedIDMap[prev.ID] = n.ID
			}
			if n.UserAlias == "" {
				n.UserAlias = prev.UserAlias
			}
			if !n.Favorite {
				n.Favorite = prev.Favorite
			}
			if n.DetourID == "" {
				n.DetourID = prev.DetourID
			}
			if n.EnginePref == "" {
				n.EnginePref = prev.EnginePref
			}
			if n.Group == "" {
				n.Group = prev.Group
			}
			if len(n.Tags) == 0 && len(prev.Tags) > 0 {
				n.Tags = append([]string(nil), prev.Tags...)
			}
			if n.Latency == 0 {
				n.Latency = prev.Latency
			}
			if n.PingMS == 0 {
				n.PingMS = prev.PingMS
			}
			if n.DownSpeedMbps == 0 {
				n.DownSpeedMbps = prev.DownSpeedMbps
			}
			if n.UpSpeedMbps == 0 {
				n.UpSpeedMbps = prev.UpSpeedMbps
			}
		}
	}
	if len(migratedIDMap) > 0 {
		for _, n := range filteredNodes {
			if nextDetour, ok := migratedIDMap[n.DetourID]; ok {
				n.DetourID = nextDetour
			}
		}
	}

	diff := computeSubscriptionDiff(prevNodes, filteredNodes, filteredOut)

	if err := s.store.SyncSubscriptionNodes(v.ID, filteredNodes); err != nil {
		return nil, err
	}
	if len(migratedIDMap) > 0 {
		if prevGroupsErr == nil {
			for _, g := range prevGroups {
				changed := false
				if nextSel, ok := migratedIDMap[g.SelectedNodeID]; ok {
					g.SelectedNodeID = nextSel
					changed = true
				}
				if nextDetour, ok := migratedIDMap[g.DetourID]; ok {
					g.DetourID = nextDetour
					changed = true
				}
				for idx, nid := range g.NodeIDs {
					if nextID, ok := migratedIDMap[nid]; ok {
						g.NodeIDs[idx] = nextID
						changed = true
					}
				}
				if changed {
					_ = s.store.SaveGroup(g)
				}
			}
		}
		for _, l := range prevListeners {
			if l == nil {
				continue
			}
			changed := false
			for idx, nid := range l.NodeIDs {
				if nextID, ok := migratedIDMap[nid]; ok {
					l.NodeIDs[idx] = nextID
					changed = true
				}
			}
			if changed {
				_ = s.store.UpdateListener(l)
			}
		}
		for _, other := range s.store.List() {
			if other == nil {
				continue
			}
			if nextDetour, ok := migratedIDMap[other.DetourID]; ok {
				cp := *other
				cp.DetourID = nextDetour
				_ = s.store.Update(&cp)
			}
		}
		if prevTSErr == nil {
			if nextTSDetour, ok := migratedIDMap[prevTS.DetourID]; ok {
				prevTS.DetourID = nextTSDetour
				prevTS.AuthKey = ""
				prevTS.HasAuthKey = false
				prevTS.ClearAuthKey = false
				_ = s.store.PutSetting(tailscaleSettingKey, prevTS)
			}
		}
		rs := s.runtimeState()
		if nextActive, ok := migratedIDMap[rs.activeNodeID]; ok {
			s.persistRuntimeSelection(nextActive, rs.activeGroupID, rs.tunEnabled)
		}
	}
	s.recordSubscriptionRefreshResult(v.ID, nil)

	v.UploadBytes = meta.UploadBytes
	v.DownloadBytes = meta.DownloadBytes
	v.TotalBytes = meta.TotalBytes
	v.ExpireUnix = meta.ExpireUnix
	v.ImportedCount = len(filteredNodes)
	v.SkippedCount = len(res.Skipped) + filteredOut
	v.Warnings = res.Warnings
	if v.Warnings == nil {
		v.Warnings = []string{}
	}
	if filteredOut > 0 {
		v.Warnings = append(v.Warnings, fmt.Sprintf("Regex filter excluded %d node(s)", filteredOut))
	}
	v.LastUpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := s.store.SaveSubscription(*v); err != nil {
		return nil, err
	}
	if reconcileNow && s.ensureOrchestrator().Status().Running {
		s.opMu.Lock()
		rs := s.runtimeState()
		_, _ = s.reconcileRuntime(ctx, rs.activeNodeID, rs.activeGroupID, rs.tunEnabled)
		s.opMu.Unlock()
	}
	return &diff, nil
}

func (s *Server) handleRefreshSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	sub, found, err := s.store.GetSubscription(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "subscription not found", http.StatusNotFound)
		return
	}
	diff, err := s.refreshSubscriptionWithDiff(r.Context(), sub, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, SubscriptionRefreshResponse{
		Subscription: *sub,
		Diff:         diff,
	})
}

func (s *Server) handleRefreshAllSubscriptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	subs, err := s.subscriptions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type itemResult struct {
		ID    string            `json:"id"`
		Name  string            `json:"name"`
		Diff  *SubscriptionDiff `json:"diff,omitempty"`
		Error string            `json:"error,omitempty"`
	}
	results := make([]itemResult, len(subs))
	var (
		wg        sync.WaitGroup
		sem       = make(chan struct{}, 4)
		succeeded int
		failed    int
		totAdd    int
		totRem    int
		totRen    int
		mu        sync.Mutex
	)
	for i := range subs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			sub := subs[idx]
			diff, rErr := s.refreshSubscriptionWithDiff(r.Context(), &sub, false)
			mu.Lock()
			if rErr != nil {
				failed++
				results[idx] = itemResult{ID: sub.ID, Name: sub.Name, Error: rErr.Error()}
			} else {
				succeeded++
				if diff != nil {
					totAdd += diff.Added
					totRem += diff.Removed
					totRen += diff.Renamed
				}
				results[idx] = itemResult{ID: sub.ID, Name: sub.Name, Diff: diff}
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	reloaded := false
	if succeeded > 0 && s.ensureOrchestrator().Status().Running {
		s.opMu.Lock()
		rs := s.runtimeState()
		if _, recErr := s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, rs.tunEnabled); recErr == nil {
			reloaded = true
		}
		s.opMu.Unlock()
	}

	updatedSubs, _ := s.subscriptions()
	writeJSON(w, http.StatusOK, map[string]any{
		"total":         len(subs),
		"succeeded":     succeeded,
		"failed":        failed,
		"reloaded":      reloaded,
		"diff":          SubscriptionDiff{Added: totAdd, Removed: totRem, Renamed: totRen},
		"results":       results,
		"subscriptions": updatedSubs,
	})
}

// RunMaintenance executes periodic background tasks for subscriptions, rule sets, traffic ledger,
// health monitoring, Kill Switch, and core update checks.
func (s *Server) RunMaintenance(ctx context.Context) {
	tickInterval := 15 * time.Second
	if s.isAndroidPowerMode() {
		tickInterval = 60 * time.Second
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.isVaultLocked() {
				continue
			}
			now := time.Now()
			subs, err := s.subscriptions()
			if err == nil {
				for i := range subs {
					if subs[i].AutoUpdateHours <= 0 {
						continue
					}
					if s.shouldSkipSubscriptionAutoUpdate(subs[i].ID, now) {
						continue
					}
					last, parseErr := time.Parse(time.RFC3339, subs[i].LastUpdatedAt)
					if subs[i].LastUpdatedAt == "" || parseErr != nil || time.Since(last) >= time.Duration(subs[i].AutoUpdateHours)*time.Hour {
						rErr := s.refreshSubscription(ctx, &subs[i])
						s.recordSubscriptionRefreshResult(subs[i].ID, rErr)
					}
				}
			}
			s.maintainRuleSets(ctx)
			s.ensureTrafficLedger().MaybeFlush()
			s.maintainKillSwitch(ctx)
			s.maintainHealth(ctx)
			s.maintainCoreUpdates(ctx)
		}
	}
}

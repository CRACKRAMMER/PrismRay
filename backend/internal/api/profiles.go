// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

const (
	activeProfileSettingKey = "routing.active_profile_id"
	profilesMetaSettingKey  = "routing.profiles_meta"
	defaultProfileID        = "default"
)

// RoutingProfileMeta stores lightweight metadata and optional bindings for a named routing scene profile.
type RoutingProfileMeta struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	PreferredNodeID  string `json:"preferred_node_id,omitempty"`
	PreferredGroupID string `json:"preferred_group_id,omitempty"`
	TailscaleEnabled *bool  `json:"tailscale_enabled,omitempty"`
	CreatedAt        string `json:"created_at,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

// RoutingProfileSummary combines profile metadata with key fields of its routing document.
type RoutingProfileSummary struct {
	RoutingProfileMeta
	Active          bool   `json:"active"`
	Mode            string `json:"mode"`
	CustomRuleCount int    `json:"custom_rule_count"`
	FakeIP          bool   `json:"fake_ip"`
	KillSwitch      bool   `json:"kill_switch"`
	BypassCN        bool   `json:"bypass_cn"`
	BlockAds        bool   `json:"block_ads"`
}

func (s *Server) activeRoutingProfileID() string {
	s.stateMu.RLock()
	id := strings.TrimSpace(s.activeProfileID)
	s.stateMu.RUnlock()
	if id != "" {
		return id
	}
	return defaultProfileID
}

func (s *Server) setActiveRoutingProfileID(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		id = defaultProfileID
	}
	s.stateMu.Lock()
	s.activeProfileID = id
	s.stateMu.Unlock()
}

func (s *Server) routingProfileByID(id string) (ruleset.RoutingProfile, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		id = defaultProfileID
	}
	profile := ruleset.DefaultRoutingProfile()
	if s.isAndroidPowerMode() {
		profile.LogLevel = "warn"
	}
	if s.store == nil {
		return profile, nil
	}
	rec, found, err := s.store.GetRoutingProfile(id)
	if err != nil {
		return profile, err
	}
	if !found || len(rec.Document) == 0 {
		return profile, nil
	}
	if err := json.Unmarshal(rec.Document, &profile); err != nil {
		fallback := ruleset.DefaultRoutingProfile()
		if s.isAndroidPowerMode() {
			fallback.LogLevel = "warn"
		}
		return fallback, err
	}
	profile.Normalize()
	return profile, nil
}

func (s *Server) saveRoutingProfileByID(id string, profile ruleset.RoutingProfile) error {
	id = strings.TrimSpace(id)
	if id == "" {
		id = defaultProfileID
	}
	profile.Normalize()
	if id == s.activeRoutingProfileID() {
		s.setCachedRoutingMode(profile.Mode)
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	if s.store == nil {
		return nil
	}
	return s.store.SaveRoutingProfile(storage.RoutingProfileRecord{
		ID:       id,
		Document: raw,
	})
}

func (s *Server) listProfileMetas() ([]RoutingProfileMeta, error) {
	var metas []RoutingProfileMeta
	if s.store != nil {
		found, err := s.store.GetSetting(profilesMetaSettingKey, &metas)
		if err != nil {
			return nil, err
		}
		if !found || len(metas) == 0 {
			metas = nil
		}
	}
	if len(metas) == 0 {
		now := time.Now().UTC().Format(time.RFC3339)
		metas = []RoutingProfileMeta{{
			ID:        defaultProfileID,
			Name:      "Default",
			CreatedAt: now,
			UpdatedAt: now,
		}}
	}
	activeID := s.activeRoutingProfileID()
	hasActive := false
	for _, m := range metas {
		if m.ID == activeID {
			hasActive = true
			break
		}
	}
	if !hasActive {
		s.setActiveRoutingProfileID(metas[0].ID)
		if s.store != nil {
			_ = s.store.PutSetting(activeProfileSettingKey, metas[0].ID)
		}
	}
	return metas, nil
}

func (s *Server) saveProfileMetas(metas []RoutingProfileMeta) error {
	if s.store == nil {
		return nil
	}
	return s.store.PutSetting(profilesMetaSettingKey, metas)
}

func (s *Server) profileSummaries() ([]RoutingProfileSummary, string, error) {
	metas, err := s.listProfileMetas()
	if err != nil {
		return nil, defaultProfileID, err
	}
	activeID := s.activeRoutingProfileID()
	out := make([]RoutingProfileSummary, 0, len(metas))
	for _, m := range metas {
		doc, _ := s.routingProfileByID(m.ID)
		out = append(out, RoutingProfileSummary{
			RoutingProfileMeta: m,
			Active:             m.ID == activeID,
			Mode:               doc.Mode,
			CustomRuleCount:    len(doc.CustomRules),
			FakeIP:             doc.FakeIP,
			KillSwitch:         doc.KillSwitchEnabled(),
			BypassCN:           doc.BypassCN,
			BlockAds:           doc.BlockAds,
		})
	}
	return out, activeID, nil
}

func buildTemplateRoutingProfile(template string, base ruleset.RoutingProfile, androidPower bool) ruleset.RoutingProfile {
	p := base
	switch strings.ToLower(strings.TrimSpace(template)) {
	case "office":
		p = ruleset.DefaultRoutingProfile()
		p.Mode = "rule"
		p.BypassLAN = true
		p.AllowLANBroadcast = true
		p.BypassCN = true
		p.BlockAds = true
		p.FakeIP = false
	case "home":
		p = ruleset.DefaultRoutingProfile()
		p.Mode = "rule"
		p.BypassLAN = true
		p.AllowLANBroadcast = false
		p.BypassCN = true
		p.BlockAds = true
		p.FakeIP = false
	case "travel":
		p = ruleset.DefaultRoutingProfile()
		p.Mode = "global"
		p.BypassLAN = true
		p.AllowLANBroadcast = false
		p.BypassCN = false
		p.BlockAds = true
		p.KillSwitch = ruleset.BoolPtr(true)
		p.WebRTCMode = "block"
	default:
		// Keep cloned base document.
	}
	if androidPower && strings.TrimSpace(p.LogLevel) == "info" {
		p.LogLevel = "warn"
	}
	p.Normalize()
	return p
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		profiles, activeID, err := s.profileSummaries()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"active_id": activeID,
			"profiles":  profiles,
		})

	case http.MethodPost:
		var req struct {
			Name             string `json:"name"`
			CloneFromID      string `json:"clone_from_id,omitempty"`
			Template         string `json:"template,omitempty"` // "" | "default" | "office" | "home" | "travel"
			PreferredNodeID  string `json:"preferred_node_id,omitempty"`
			PreferredGroupID string `json:"preferred_group_id,omitempty"`
			TailscaleEnabled *bool  `json:"tailscale_enabled,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			http.Error(w, "profile name is required", http.StatusBadRequest)
			return
		}

		s.opMu.Lock()
		defer s.opMu.Unlock()

		metas, err := s.listProfileMetas()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, m := range metas {
			if strings.EqualFold(strings.TrimSpace(m.Name), name) {
				http.Error(w, "profile name already exists", http.StatusConflict)
				return
			}
		}

		cloneID := strings.TrimSpace(req.CloneFromID)
		if cloneID == "" {
			cloneID = s.activeRoutingProfileID()
		}
		baseDoc, _ := s.routingProfileByID(cloneID)
		doc := buildTemplateRoutingProfile(req.Template, baseDoc, s.isAndroidPowerMode())

		now := time.Now().UTC().Format(time.RFC3339)
		newID := newRandomID("prof-")
		meta := RoutingProfileMeta{
			ID:               newID,
			Name:             name,
			PreferredNodeID:  strings.TrimSpace(req.PreferredNodeID),
			PreferredGroupID: strings.TrimSpace(req.PreferredGroupID),
			TailscaleEnabled: req.TailscaleEnabled,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		if err := s.saveRoutingProfileByID(newID, doc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		metas = append(metas, meta)
		if err := s.saveProfileMetas(metas); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		profiles, activeID, err := s.profileSummaries()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"created_id": newID,
			"active_id":  activeID,
			"profiles":   profiles,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProfileItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "profile id is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPut:
		var req struct {
			Name             *string `json:"name,omitempty"`
			PreferredNodeID  *string `json:"preferred_node_id,omitempty"`
			PreferredGroupID *string `json:"preferred_group_id,omitempty"`
			TailscaleEnabled *bool   `json:"tailscale_enabled,omitempty"`
			ClearTailscale   bool    `json:"clear_tailscale_enabled,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.opMu.Lock()
		defer s.opMu.Unlock()

		metas, err := s.listProfileMetas()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		idx := -1
		for i := range metas {
			if metas[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}
		if req.Name != nil {
			newName := strings.TrimSpace(*req.Name)
			if newName == "" {
				http.Error(w, "profile name cannot be empty", http.StatusBadRequest)
				return
			}
			for i, m := range metas {
				if i != idx && strings.EqualFold(strings.TrimSpace(m.Name), newName) {
					http.Error(w, "profile name already exists", http.StatusConflict)
					return
				}
			}
			metas[idx].Name = newName
		}
		if req.PreferredNodeID != nil {
			metas[idx].PreferredNodeID = strings.TrimSpace(*req.PreferredNodeID)
			if metas[idx].PreferredNodeID != "" {
				metas[idx].PreferredGroupID = ""
			}
		}
		if req.PreferredGroupID != nil {
			metas[idx].PreferredGroupID = strings.TrimSpace(*req.PreferredGroupID)
			if metas[idx].PreferredGroupID != "" {
				metas[idx].PreferredNodeID = ""
			}
		}
		if req.ClearTailscale {
			metas[idx].TailscaleEnabled = nil
		} else if req.TailscaleEnabled != nil {
			v := *req.TailscaleEnabled
			metas[idx].TailscaleEnabled = &v
		}
		metas[idx].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := s.saveProfileMetas(metas); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		profiles, activeID, err := s.profileSummaries()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"active_id": activeID,
			"profiles":  profiles,
		})

	case http.MethodDelete:
		s.opMu.Lock()
		defer s.opMu.Unlock()

		metas, err := s.listProfileMetas()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(metas) <= 1 {
			http.Error(w, "cannot delete the last remaining routing profile", http.StatusBadRequest)
			return
		}
		idx := -1
		for i := range metas {
			if metas[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}

		nextMetas := append(metas[:idx], metas[idx+1:]...)
		if err := s.saveProfileMetas(nextMetas); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if s.store != nil {
			_ = s.store.DeleteRoutingProfile(id)
		}

		switched := false
		if s.activeRoutingProfileID() == id {
			fallbackID := nextMetas[0].ID
			s.setActiveRoutingProfileID(fallbackID)
			if s.store != nil {
				_ = s.store.PutSetting(activeProfileSettingKey, fallbackID)
			}
			doc, _ := s.routingProfileByID(fallbackID)
			s.setCachedRoutingMode(doc.Mode)
			switched = true
			if s.ensureOrchestrator().Status().Running {
				rs := s.runtimeState()
				_, _ = s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, rs.tunEnabled)
			}
		}
		profiles, activeID, err := s.profileSummaries()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"active_id": activeID,
			"switched":  switched,
			"profiles":  profiles,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleActivateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "profile id is required", http.StatusBadRequest)
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	metas, err := s.listProfileMetas()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var target *RoutingProfileMeta
	for i := range metas {
		if metas[i].ID == id {
			cp := metas[i]
			target = &cp
			break
		}
	}
	if target == nil {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}

	prevProfileID := s.activeRoutingProfileID()
	prevState := s.runtimeState()
	prevTSCfg, prevTSErr := s.tailscaleConfig(true)

	s.setActiveRoutingProfileID(id)
	if s.store != nil {
		if err := s.store.PutSetting(activeProfileSettingKey, id); err != nil {
			s.setActiveRoutingProfileID(prevProfileID)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	routing, err := s.routingProfile()
	if err != nil {
		s.setActiveRoutingProfileID(prevProfileID)
		if s.store != nil {
			_ = s.store.PutSetting(activeProfileSettingKey, prevProfileID)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	nextNodeID := prevState.activeNodeID
	nextGroupID := prevState.activeGroupID
	if target.PreferredGroupID != "" && s.store != nil {
		if groups, gErr := s.store.ListGroups(); gErr == nil {
			for _, g := range groups {
				if g.ID == target.PreferredGroupID {
					nextGroupID = g.ID
					nextNodeID = ""
					break
				}
			}
		}
	} else if target.PreferredNodeID != "" && s.store != nil {
		if s.store.Get(target.PreferredNodeID) != nil {
			nextNodeID = target.PreferredNodeID
			nextGroupID = ""
		}
	}

	tsChanged := false
	if target.TailscaleEnabled != nil && prevTSErr == nil && prevTSCfg.Enabled != *target.TailscaleEnabled && s.store != nil {
		updatedTS := prevTSCfg
		updatedTS.Enabled = *target.TailscaleEnabled
		updatedTS.AuthKey = ""
		updatedTS.HasAuthKey = false
		updatedTS.ClearAuthKey = false
		if err := s.store.PutSetting(tailscaleSettingKey, updatedTS); err == nil {
			tsChanged = true
		}
	}

	reloaded := false
	if s.ensureOrchestrator().Status().Running {
		if _, recErr := s.reconcileRuntime(r.Context(), nextNodeID, nextGroupID, prevState.tunEnabled); recErr != nil {
			// Roll back active profile and Tailscale toggle on runtime apply failure.
			s.setActiveRoutingProfileID(prevProfileID)
			if s.store != nil {
				_ = s.store.PutSetting(activeProfileSettingKey, prevProfileID)
			}
			if tsChanged && s.store != nil {
				rbTS := prevTSCfg
				rbTS.AuthKey = ""
				rbTS.HasAuthKey = false
				rbTS.ClearAuthKey = false
				_ = s.store.PutSetting(tailscaleSettingKey, rbTS)
			}
			_, _ = s.routingProfile()
			respondError(w, recErr, http.StatusBadGateway)
			return
		}
		reloaded = true
	} else if nextNodeID != prevState.activeNodeID || nextGroupID != prevState.activeGroupID {
		s.persistRuntimeSelection(nextNodeID, nextGroupID, prevState.tunEnabled)
	}

	profiles, activeID, _ := s.profileSummaries()
	writeJSON(w, http.StatusOK, map[string]any{
		"active_id": activeID,
		"reloaded":  reloaded,
		"routing":   routing,
		"profiles":  profiles,
	})
}

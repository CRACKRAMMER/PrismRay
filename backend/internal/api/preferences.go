// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	xc "github.com/CRACKRAMMER/PrismRay/backend/internal/xray/config"
)

func (s *Server) preferences() (xc.Preferences, error) {
	p := xc.Preferences{
		Mode:           "rule",
		LogLevel:       "warning",
		Rules:          []xc.RoutingRule{},
		DNSServers:     []string{"1.1.1.1", "8.8.8.8"},
		DomainStrategy: "IPIfNonMatch",
	}
	if s.store != nil {
		if found, err := s.store.GetSetting("app.preferences", &p); err != nil {
			return p, err
		} else if found {
			return p, nil
		}
	}
	profile, err := s.routingProfile()
	if err == nil {
		switch profile.Mode {
		case "global", "direct", "rule":
			p.Mode = profile.Mode
		}
		if profile.LogLevel != "" {
			p.LogLevel = profile.LogLevel
		}
	}
	return p, nil
}

func syncRoutingFromPreferences(profile ruleset.RoutingProfile, p xc.Preferences) ruleset.RoutingProfile {
	switch p.Mode {
	case "global", "direct", "rule":
		profile.Mode = p.Mode
	case "bypass-lan":
		profile.Mode = "rule"
		profile.BypassLAN = true
	case "bypass-cn":
		profile.Mode = "rule"
		profile.BypassCN = true
	}
	switch p.LogLevel {
	case "debug", "info", "error":
		profile.LogLevel = p.LogLevel
	case "warning":
		profile.LogLevel = "warn"
	}
	switch p.DomainStrategy {
	case "AsIs":
		profile.DomainStrategy = "as_is"
	case "IPIfNonMatch", "IPOnDemand":
		profile.DomainStrategy = "prefer_ipv4"
	}
	if len(p.DNSServers) > 0 && strings.TrimSpace(p.DNSServers[0]) != "" {
		profile.RemoteDNS = strings.TrimSpace(p.DNSServers[0])
	}
	profile.Normalize()
	return profile
}

func (s *Server) handlePreferences(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		p, err := s.preferences()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, p)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var p xc.Preferences
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := p.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	oldPrefs, _ := s.preferences()
	oldProfile, _ := s.routingProfile()

	if err := s.store.PutSetting("app.preferences", p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	updatedProfile := syncRoutingFromPreferences(oldProfile, p)
	if err := s.saveRoutingProfile(updatedProfile); err != nil {
		_ = s.store.PutSetting("app.preferences", oldPrefs)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.opMu.Lock()
	running := s.ensureOrchestrator().Status().Running
	var applyErr error
	if running {
		rs := s.runtimeState()
		_, applyErr = s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, rs.tunEnabled)
		if applyErr != nil {
			_ = s.store.PutSetting("app.preferences", oldPrefs)
			_ = s.saveRoutingProfile(oldProfile)
		}
	}
	s.opMu.Unlock()

	if applyErr != nil {
		http.Error(w, "应用失败，已恢复旧设置："+applyErr.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

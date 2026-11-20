// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/autostart"
)

func (s *Server) autostartManager() *autostart.Manager {
	return &autostart.Manager{}
}

func (s *Server) handleAutostart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.mode != authservice.ModeDesktop {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, autostart.Status{
				Supported: false,
				Reason:    "仅桌面客户端支持开机自启动",
			})
			return
		}
		http.Error(w, "仅桌面客户端支持开机自启动", http.StatusBadRequest)
		return
	}

	mgr := s.autostartManager()
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, mgr.Status())
		return
	}

	var req struct {
		Enabled   bool  `json:"enabled"`
		Minimized *bool `json:"minimized"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	minimized := mgr.Status().Minimized
	if req.Minimized != nil {
		minimized = *req.Minimized
	}

	st, err := mgr.Set(req.Enabled, minimized)
	if err != nil {
		respondError(w, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/systemproxy"
)

func (s *Server) proxyManager() *systemproxy.Manager {
	dir := ""
	if s.cfg != nil {
		dir = s.cfg.RuntimeDir()
	} else if s.store != nil {
		dir = filepath.Dir(s.store.Path())
	}
	return &systemproxy.Manager{Path: filepath.Join(dir, "system-proxy.json")}
}

// RestoreSystemProxy restores saved OS proxy settings if enabled earlier.
func (s *Server) RestoreSystemProxy() error {
	return s.proxyManager().Restore()
}

func (s *Server) handleSystemProxy(w http.ResponseWriter, r *http.Request) {
	m := s.proxyManager()
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":    m.Active(),
			"remembered": s.systemProxyWanted,
			"port":       s.ensureOrchestrator().Status().MixedPort,
		})
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var err error
	if req.Enabled {
		s.opMu.Lock()
		st := s.ensureOrchestrator().Status()
		if !st.Running && s.store != nil && len(s.store.List()) > 0 {
			if reconciled, recErr := s.reconcileRuntime(r.Context(), s.activeNodeID, s.activeGroupID, s.tunEnabled); recErr == nil {
				st = reconciled
			}
		}
		s.opMu.Unlock()

		port := st.MixedPort
		if port <= 0 && s.cfg != nil {
			port = s.cfg.SingBox.MixedPort
		}
		if !st.Running || port <= 0 {
			http.Error(w, "请先启动代理连接再开启系统代理", http.StatusConflict)
			return
		}
		s.persistSystemProxyWanted(true)
		if !m.Active() {
			err = m.Enable(port)
		}
	} else {
		s.persistSystemProxyWanted(false)
		err = m.Restore()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    m.Active(),
		"remembered": s.systemProxyWanted,
	})
}

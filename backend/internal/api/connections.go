// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/clashapi"
	"github.com/gorilla/websocket"
)

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if websocket.IsWebSocketUpgrade(r) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(req *http.Request) bool { return s.originAllowed(req) },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		disconnected := watchDisconnect(conn)
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		var snapCh <-chan clashapi.ConnectionsSnapshot
		var errCh <-chan error
		if client := s.ensureOrchestrator().ClashClient(); client != nil {
			snapCh, errCh = client.StreamConnections(ctx, 1000)
		} else {
			_ = conn.WriteJSON(clashapi.ConnectionsSnapshot{Connections: []clashapi.ConnectionItem{}})
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-disconnected:
				return
			case <-ctx.Done():
				return
			case snap, ok := <-snapCh:
				if !ok {
					snapCh = nil
					continue
				}
				if snap.Connections == nil {
					snap.Connections = []clashapi.ConnectionItem{}
				}
				if err := conn.WriteJSON(snap); err != nil {
					return
				}
			case <-errCh:
				return
			case <-ticker.C:
				if snapCh == nil {
					if client := s.ensureOrchestrator().ClashClient(); client != nil {
						snapCh, errCh = client.StreamConnections(ctx, 1000)
					} else {
						if err := conn.WriteJSON(clashapi.ConnectionsSnapshot{Connections: []clashapi.ConnectionItem{}}); err != nil {
							return
						}
					}
				}
			}
		}
	}

	switch r.Method {
	case http.MethodGet:
		client := s.ensureOrchestrator().ClashClient()
		if client == nil {
			writeJSON(w, http.StatusOK, clashapi.ConnectionsSnapshot{Connections: []clashapi.ConnectionItem{}})
			return
		}
		snap, err := client.GetConnections(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if snap.Connections == nil {
			snap.Connections = []clashapi.ConnectionItem{}
		}
		writeJSON(w, http.StatusOK, snap)
	case http.MethodDelete:
		id := strings.TrimSpace(r.PathValue("id"))
		client := s.ensureOrchestrator().ClashClient()
		if client == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var err error
		if id != "" {
			err = client.CloseConnection(r.Context(), id)
		} else {
			err = client.CloseAllConnections(r.Context())
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) originAllowed(r *http.Request) bool {
	if s.cfg == nil {
		return true
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	for _, allowed := range s.cfg.Server.AllowedOrigins {
		if allowed == origin {
			return true
		}
	}
	return false
}

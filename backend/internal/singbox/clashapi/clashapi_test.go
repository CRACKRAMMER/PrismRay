// SPDX-License-Identifier: MPL-2.0

package clashapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestClashAPIRESTAndWebSockets(t *testing.T) {
	const secret = "test-clash-secret"
	var selectedGroup, selectedTarget string
	var closedID string
	var closedAll bool
	var patchedMode string

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		tokenQuery := r.URL.Query().Get("token")
		if authHeader != "Bearer "+secret && tokenQuery != secret {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/proxies":
			_ = json.NewEncoder(w).Encode(ProxiesResponse{
				Proxies: map[string]ProxyInfo{
					"proxy": {Name: "proxy", Type: "Selector", Now: "node-1", All: []string{"node-1", "node-2"}},
				},
			})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/proxies/"):
			selectedGroup = strings.TrimPrefix(r.URL.Path, "/proxies/")
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			selectedTarget = body.Name
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/delay"):
			_ = json.NewEncoder(w).Encode(map[string]int{"delay": 127})
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			if websocket.IsWebSocketUpgrade(r) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.WriteJSON(ConnectionsSnapshot{
					DownloadTotal: 4096,
					UploadTotal:   1024,
					Connections: []ConnectionItem{
						{
							ID:       "conn-1",
							Metadata: ConnectionMetadata{Network: "tcp", Host: "example.com", DestinationPort: "443"},
							Chains:   []string{"node-1", "proxy"},
							Rule:     "geosite-geolocation-!cn",
						},
					},
				})
				time.Sleep(150 * time.Millisecond)
				return
			}
			_ = json.NewEncoder(w).Encode(ConnectionsSnapshot{
				DownloadTotal: 100,
				UploadTotal:   50,
				Connections: []ConnectionItem{
					{ID: "c1", Metadata: ConnectionMetadata{Host: "one.one.one.one"}},
				},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/connections":
			closedAll = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/"):
			closedID = strings.TrimPrefix(r.URL.Path, "/connections/")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPatch && r.URL.Path == "/configs":
			var body struct {
				Mode string `json:"mode"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			patchedMode = body.Mode
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/traffic":
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.WriteJSON(TrafficFrame{Up: 1200, Down: 9800})
			time.Sleep(150 * time.Millisecond)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := New(srv.URL, secret)
	ctx := context.Background()

	proxies, err := client.GetProxies(ctx)
	if err != nil {
		t.Fatalf("GetProxies error = %v", err)
	}
	if proxies.Proxies["proxy"].Now != "node-1" {
		t.Fatalf("unexpected proxy info: %+v", proxies.Proxies["proxy"])
	}

	if err := client.SelectProxy(ctx, "proxy", "node-2"); err != nil {
		t.Fatalf("SelectProxy error = %v", err)
	}
	if selectedGroup != "proxy" || selectedTarget != "node-2" {
		t.Fatalf("SelectProxy recorded %q -> %q", selectedGroup, selectedTarget)
	}

	delay, err := client.ProbeDelay(ctx, "node-2", "", 3000)
	if err != nil || delay != 127 {
		t.Fatalf("ProbeDelay = (%d, %v), want (127, nil)", delay, err)
	}

	snap, err := client.GetConnections(ctx)
	if err != nil || len(snap.Connections) != 1 || snap.Connections[0].ID != "c1" {
		t.Fatalf("GetConnections = (%+v, %v)", snap, err)
	}

	if err := client.CloseConnection(ctx, "c1"); err != nil || closedID != "c1" {
		t.Fatalf("CloseConnection err=%v id=%q", err, closedID)
	}
	if err := client.CloseAllConnections(ctx); err != nil || !closedAll {
		t.Fatalf("CloseAllConnections err=%v closedAll=%v", err, closedAll)
	}
	if err := client.SetMode(ctx, "Global"); err != nil || patchedMode != "Global" {
		t.Fatalf("SetMode err=%v mode=%q", err, patchedMode)
	}

	tCtx, tCancel := context.WithTimeout(ctx, 2*time.Second)
	defer tCancel()
	frames, errs := client.StreamTraffic(tCtx)
	select {
	case frame, ok := <-frames:
		if !ok || frame.Up != 1200 || frame.Down != 9800 {
			t.Fatalf("unexpected traffic frame: %+v (ok=%v)", frame, ok)
		}
	case err := <-errs:
		t.Fatalf("StreamTraffic error: %v", err)
	case <-tCtx.Done():
		t.Fatal("timed out waiting for traffic frame")
	}

	cCtx, cCancel := context.WithTimeout(ctx, 2*time.Second)
	defer cCancel()
	snaps, cErrs := client.StreamConnections(cCtx, 500)
	select {
	case wsSnap, ok := <-snaps:
		if !ok || len(wsSnap.Connections) != 1 || wsSnap.Connections[0].ID != "conn-1" {
			t.Fatalf("unexpected ws snapshot: %+v (ok=%v)", wsSnap, ok)
		}
	case err := <-cErrs:
		t.Fatalf("StreamConnections error: %v", err)
	case <-cCtx.Done():
		t.Fatal("timed out waiting for ws connections snapshot")
	}
}

// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/keyring"
	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/process"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/stats"
)

func newWebAuthServer(t *testing.T) (*Server, *storage.Store, *authservice.Manager) {
	t.Helper()
	dir := t.TempDir()
	cfg := appconfig.Default()
	cfg.Storage.DatabasePath = filepath.Join(dir, "prismray.db")
	store, err := storage.NewStore(cfg.Storage.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	authMgr, err := authservice.New(store, "bootstrap-test")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(process.NewManager(filepath.Join(dir, "xray.json")), store, stats.NewClient("", "127.0.0.1:0"), cfg)
	s.SetAuth(authMgr)
	s.SetMode(authservice.ModeWeb)
	return s, store, authMgr
}

func TestFirstRunAuthenticationProtectsAPI(t *testing.T) {
	s, _, _ := newWebAuthServer(t)

	if got := request(s, http.MethodGet, "/api/nodes", "").Code; got != http.StatusPreconditionRequired {
		t.Fatalf("expected 428 before init, got %d", got)
	}

	initRequest := httptest.NewRequest(http.MethodPost, "/api/auth/initialize", strings.NewReader(`{"password":"test-password","bootstrap_token":"bootstrap-test"}`))
	initResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(initResponse, initRequest)
	if initResponse.Code != http.StatusOK || len(initResponse.Result().Cookies()) == 0 {
		t.Fatalf("initialize failed: %d %s", initResponse.Code, initResponse.Body.String())
	}

	if got := request(s, http.MethodGet, "/api/nodes", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("expected 401 without cookie, got %d", got)
	}

	statusRequest := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	statusResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(statusResponse, statusRequest)
	var status map[string]any
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal status failed: %v", err)
	}
	if status["authenticated"] == true || status["mode"] != "web" {
		t.Fatalf("status exposed another session as authenticated or wrong mode: %v", status)
	}

	authed := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	authed.AddCookie(initResponse.Result().Cookies()[0])
	authedResp := httptest.NewRecorder()
	s.Handler().ServeHTTP(authedResp, authed)
	if authedResp.Code != http.StatusOK {
		t.Fatalf("authenticated request failed: %d %s", authedResp.Code, authedResp.Body.String())
	}

	statusRequest = httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	statusRequest.AddCookie(initResponse.Result().Cookies()[0])
	statusResponse = httptest.NewRecorder()
	s.Handler().ServeHTTP(statusResponse, statusRequest)
	status = map[string]any{}
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal authed status failed: %v", err)
	}
	if status["authenticated"] != true || status["unlocked"] != true {
		t.Fatalf("authenticated status was not preserved: %v", status)
	}

	lockReq := httptest.NewRequest(http.MethodPost, "/api/auth/lock", nil)
	lockReq.AddCookie(initResponse.Result().Cookies()[0])
	lockResp := httptest.NewRecorder()
	s.Handler().ServeHTTP(lockResp, lockReq)
	if lockResp.Code != http.StatusNoContent && lockResp.Code != http.StatusOK {
		t.Fatalf("lock failed: %d %s", lockResp.Code, lockResp.Body.String())
	}
	if got := request(s, http.MethodGet, "/api/nodes", "").Code; got != http.StatusLocked {
		t.Fatalf("expected 423 after lock, got %d", got)
	}
}

func TestDesktopAndAndroidAutoUnlockWithOptionalPasswordLock(t *testing.T) {
	for _, mode := range []string{authservice.ModeDesktop, authservice.ModeAndroid} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cfg := appconfig.Default()
			cfg.Storage.DatabasePath = filepath.Join(dir, "prismray.db")
			store, err := storage.NewStore(cfg.Storage.DatabasePath)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()

			kr := keyring.New(keyring.Options{
				Service:          "io.prismray.test",
				Account:          mode,
				FallbackPath:     filepath.Join(dir, ".device.key"),
				DisableOSKeyring: true,
			})
			authMgr, err := authservice.NewWithOptions(store, authservice.Options{Mode: mode, Keyring: kr})
			if err != nil {
				t.Fatal(err)
			}
			s := NewServer(nil, store, nil, cfg)
			s.SetAuth(authMgr)
			s.SetMode(mode)
			s.SetDesktopToken("ipc-secret-" + mode)

			r := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
			r.Header.Set("Authorization", "Bearer ipc-secret-"+mode)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			var status map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
				t.Fatal(err)
			}
			if status["mode"] != mode || status["unlocked"] != true || status["bootstrap_token_required"] != false {
				t.Fatalf("unexpected %s status: %v", mode, status)
			}

			req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
			req.Header.Set("Authorization", "Bearer ipc-secret-"+mode)
			res := httptest.NewRecorder()
			s.Handler().ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("expected auto-unlocked %s API 200, got %d %s", mode, res.Code, res.Body.String())
			}

			// Enable optional startup password lock.
			lockToggle := httptest.NewRequest(http.MethodPost, "/api/auth/password-lock", strings.NewReader(`{"enabled":true,"password":"startup-lock-pass"}`))
			lockToggle.Header.Set("Authorization", "Bearer ipc-secret-"+mode)
			ltResp := httptest.NewRecorder()
			s.Handler().ServeHTTP(ltResp, lockToggle)
			if ltResp.Code != http.StatusOK {
				t.Fatalf("password lock enable failed: %d %s", ltResp.Code, ltResp.Body.String())
			}
			authMgr.Lock()

			lockedReq := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
			lockedReq.Header.Set("Authorization", "Bearer ipc-secret-"+mode)
			lockedResp := httptest.NewRecorder()
			s.Handler().ServeHTTP(lockedResp, lockedReq)
			if lockedResp.Code != http.StatusLocked {
				t.Fatalf("expected 423 after lock, got %d", lockedResp.Code)
			}

			unlockReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"startup-lock-pass"}`))
			unlockReq.Header.Set("Authorization", "Bearer ipc-secret-"+mode)
			unlockResp := httptest.NewRecorder()
			s.Handler().ServeHTTP(unlockResp, unlockReq)
			if unlockResp.Code != http.StatusOK {
				t.Fatalf("unlock login failed: %d %s", unlockResp.Code, unlockResp.Body.String())
			}

			afterUnlock := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
			afterUnlock.Header.Set("Authorization", "Bearer ipc-secret-"+mode)
			afterResp := httptest.NewRecorder()
			s.Handler().ServeHTTP(afterResp, afterUnlock)
			if afterResp.Code != http.StatusOK {
				t.Fatalf("expected 200 after password unlock, got %d %s", afterResp.Code, afterResp.Body.String())
			}
		})
	}
}

func TestTUNAndListenerConfigurationCanCoexist(t *testing.T) {
	n := &config.Node{
		ID:       "n1",
		Name:     "VLESS Edge",
		Protocol: config.ProtocolVLESS,
		Address:  "1.2.3.4",
		Port:     443,
		UUID:     "11111111-1111-1111-1111-111111111111",
		Security: "tls",
		Sni:      "example.com",
	}
	l := &config.ListenConfig{
		ID:       "l1",
		Name:     "LAN Mixed",
		Protocol: "mixed",
		Address:  "127.0.0.1",
		Port:     18080,
		Enabled:  true,
		NodeIDs:  []string{"n1"},
	}
	out, err := sbcfg.Compile(sbcfg.CompileInput{
		Nodes:        []*config.Node{n},
		Listeners:    []*config.ListenConfig{l},
		Routing:      ruleset.DefaultRoutingProfile(),
		ActiveNodeID: "n1",
		MixedPort:    10808,
		ClashAPIPort: 19090,
		EnableTUN:    true,
		TUNStack:     "system",
	})
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	doc := string(out.Raw)
	if !strings.Contains(doc, `"type": "tun"`) || !strings.Contains(doc, `"in-l1"`) {
		t.Fatalf("expected TUN and listener inbounds to coexist cleanly in compiled sing-box config, got %s", doc)
	}
}

func TestTUNRequiresCachedSudoBeforeChangingRuntime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux sudo privilege check only")
	}
	dir := t.TempDir()
	cfg := appconfig.Default()
	cfg.Storage.DatabasePath = filepath.Join(dir, "prismray.db")
	// Point explicitly at an isolated unprivileged mock binary so host-installed cap_net_admin binaries do not mask 428.
	unprivBin := filepath.Join(dir, "unpriv-sing-box")
	if wErr := os.WriteFile(unprivBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); wErr != nil {
		t.Fatal(wErr)
	}
	cfg.SingBox.BinaryPath = unprivBin
	store, err := storage.NewStore(cfg.Storage.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	authMgr, err := authservice.NewWithOptions(store, authservice.Options{
		Mode:    authservice.ModeDesktop,
		Keyring: keyring.New(keyring.Options{Service: "test", Account: "tun", FallbackPath: filepath.Join(dir, ".device.key"), DisableOSKeyring: true}),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(nil, store, nil, cfg)
	s.SetAuth(authMgr)
	s.SetMode(authservice.ModeDesktop)
	s.SetDesktopToken("tun-token")

	req := httptest.NewRequest(http.MethodPut, "/api/tun", strings.NewReader(`{"enabled":true,"node_id":"node"}`))
	req.Header.Set("Authorization", "Bearer tun-token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("expected 428 Precondition Required when Linux TUN lacks privileges or cached sudo, got %d (%s)", w.Code, w.Body.String())
	}
}

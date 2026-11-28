// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
)

const sessionCookie = "prismray_session"

func (s *Server) desktopTrusted(r *http.Request) bool {
	return s.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) == 1
}

func (s *Server) requestAuthenticated(r *http.Request) bool {
	if s.desktopTrusted(r) {
		return true
	}
	if s.auth == nil {
		return true
	}
	cookie, err := r.Cookie(sessionCookie)
	return err == nil && s.auth.Valid(cookie.Value)
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	mode := s.mode
	if mode == "" {
		if s.auth != nil {
			mode = s.auth.Mode()
		} else if s.desktop {
			mode = "desktop"
		} else {
			mode = "web"
		}
	}
	if s.auth == nil {
		json.NewEncoder(w).Encode(map[string]any{
			"mode":                  mode,
			"initialized":           true,
			"unlocked":              true,
			"authentication":        false,
			"authenticated":         true,
			"password_lock_enabled": false,
			"biometric_enabled":     false,
		})
		return
	}
	initialized, unlocked := s.auth.Status()
	authenticated := initialized && s.requestAuthenticated(r)
	passwordLocked := s.auth.PasswordLocked()
	biometricEnabled := s.auth.BiometricEnabled()
	json.NewEncoder(w).Encode(map[string]any{
		"mode":                     mode,
		"initialized":              initialized,
		"unlocked":                 unlocked && authenticated,
		"authentication":           true,
		"authenticated":            authenticated,
		"password_lock_enabled":    passwordLocked,
		"biometric_enabled":        biometricEnabled,
		"bootstrap_token_required": !s.desktop && !initialized,
	})
}

func (s *Server) handleAuthInitialize(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication unavailable", http.StatusNotImplemented)
		return
	}
	var req struct {
		Password       string `json:"password"`
		BootstrapToken string `json:"bootstrap_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.auth.Initialize(req.Password, strings.TrimSpace(req.BootstrapToken), s.desktopTrusted(r)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token, err := s.auth.Login(req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, r, token)
	json.NewEncoder(w).Encode(map[string]bool{"initialized": true, "unlocked": true})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication unavailable", http.StatusNotImplemented)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token, err := s.auth.Login(req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	setSessionCookie(w, r, token)
	go s.RestoreLastSession(context.Background())
	json.NewEncoder(w).Encode(map[string]bool{"unlocked": true})
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int((12 * time.Hour).Seconds())})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if s.auth != nil {
		if cookie, err := r.Cookie(sessionCookie); err == nil {
			s.auth.Logout(cookie.Value)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAuthLock(w http.ResponseWriter, _ *http.Request) {
	if s.auth != nil {
		if err := s.auth.TryLock(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePasswordLock(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication unavailable", http.StatusNotImplemented)
		return
	}
	var req struct {
		Enabled         bool   `json:"enabled"`
		Password        string `json:"password"`
		CurrentPassword string `json:"current_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Enabled {
		if s.auth.PasswordLocked() {
			if err := s.auth.ChangePassword(req.CurrentPassword, req.Password); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else if err := s.auth.EnablePasswordLock(req.Password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if newToken, err := s.auth.IssueSession(); err == nil && newToken != "" {
			setSessionCookie(w, r, newToken)
		}
	} else {
		pw := req.Password
		if pw == "" {
			pw = req.CurrentPassword
		}
		if err := s.auth.DisablePasswordLock(pw); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	json.NewEncoder(w).Encode(map[string]any{
		"password_lock_enabled": s.auth.PasswordLocked(),
		"biometric_enabled":     s.auth.BiometricEnabled(),
	})
}

func (s *Server) handleBiometricConfig(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication unavailable", http.StatusNotImplemented)
		return
	}
	if s.token != "" && !s.desktopTrusted(r) {
		http.Error(w, "desktop trust required", http.StatusForbidden)
		return
	}
	var req struct {
		Enabled         bool   `json:"enabled"`
		CurrentPassword string `json:"current_password"`
		HardwareWrap    bool   `json:"hardware_wrap"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	useHardware := req.HardwareWrap || s.auth.Mode() == authservice.ModeAndroid || s.mode == authservice.ModeAndroid
	if useHardware {
		kekB64, err := s.auth.SetBiometricUnlockHardware(req.Enabled, req.CurrentPassword)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := map[string]any{
			"password_lock_enabled": s.auth.PasswordLocked(),
			"biometric_enabled":     s.auth.BiometricEnabled(),
			"hardware_wrap":         true,
		}
		if kekB64 != "" {
			resp["biometric_kek"] = kekB64
		}
		json.NewEncoder(w).Encode(resp)
		return
	}
	if err := s.auth.SetBiometricUnlock(req.Enabled, req.CurrentPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"password_lock_enabled": s.auth.PasswordLocked(),
		"biometric_enabled":     s.auth.BiometricEnabled(),
	})
}

func (s *Server) handleBiometricChallenge(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication unavailable", http.StatusNotImplemented)
		return
	}
	if s.token != "" && !s.desktopTrusted(r) {
		http.Error(w, "desktop trust required", http.StatusForbidden)
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "failed to generate challenge", http.StatusInternalServerError)
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	s.bioMu.Lock()
	if s.bioChallenges == nil {
		s.bioChallenges = map[string]time.Time{}
	}
	for k, exp := range s.bioChallenges {
		if now.After(exp) {
			delete(s.bioChallenges, k)
		}
	}
	if len(s.bioChallenges) >= 32 {
		// Evict oldest/all when flooded.
		clear(s.bioChallenges)
	}
	s.bioChallenges[nonce] = now.Add(60 * time.Second)
	s.bioMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"challenge": nonce})
}

func (s *Server) verifyDesktopBiometricProof(challenge, signatureHex string) bool {
	challenge = strings.TrimSpace(challenge)
	signatureHex = strings.TrimSpace(signatureHex)
	if challenge == "" || signatureHex == "" {
		return false
	}
	s.bioMu.Lock()
	key := append([]byte(nil), s.bioHMACKey...)
	exp, exists := s.bioChallenges[challenge]
	delete(s.bioChallenges, challenge)
	s.bioMu.Unlock()
	if len(key) < 32 || !exists || time.Now().After(exp) {
		return false
	}
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(challenge))
	expected := mac.Sum(nil)
	return hmac.Equal(sigBytes, expected)
}

func (s *Server) handleBiometricUnlock(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication unavailable", http.StatusNotImplemented)
		return
	}
	// Strictly require the local Tauri desktop/android IPC token so remote/browser callers cannot invoke biometric unlock.
	if s.token != "" && !s.desktopTrusted(r) {
		http.Error(w, "desktop trust required", http.StatusForbidden)
		return
	}
	var req struct {
		BiometricKEK string `json:"biometric_kek"`
		Challenge    string `json:"challenge"`
		Signature    string `json:"signature"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	var token string
	var err error
	if s.auth.Mode() == authservice.ModeAndroid || s.mode == authservice.ModeAndroid || strings.TrimSpace(req.BiometricKEK) != "" {
		if strings.TrimSpace(req.BiometricKEK) == "" {
			http.Error(w, "hardware biometric key required", http.StatusUnauthorized)
			return
		}
		token, err = s.auth.UnlockWithBiometricKEK(strings.TrimSpace(req.BiometricKEK))
	} else {
		if !s.verifyDesktopBiometricProof(req.Challenge, req.Signature) {
			http.Error(w, "biometric challenge verification failed", http.StatusUnauthorized)
			return
		}
		token, err = s.auth.UnlockWithBiometric()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	setSessionCookie(w, r, token)
	go s.RestoreLastSession(context.Background())
	json.NewEncoder(w).Encode(map[string]bool{"unlocked": true})
}

func (s *Server) handleSudoCache(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		if err := s.store.DeleteSetting("security.sudo_password"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		http.Error(w, "sudo password is required", http.StatusBadRequest)
		return
	}
	if runtime.GOOS == "linux" {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sudo", "-S", "-k", "-p", "", "-v")
		cmd.Stdin = bytes.NewBufferString(req.Password + "\n")
		if err := cmd.Run(); err != nil {
			http.Error(w, "sudo 密码验证失败", http.StatusUnauthorized)
			return
		}
	}
	if err := s.store.PutSecret("security.sudo_password", []byte(req.Password)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]bool{"cached": true})
}

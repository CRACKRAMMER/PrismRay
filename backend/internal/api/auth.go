// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
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
		s.auth.Lock()
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
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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

func (s *Server) handleBiometricUnlock(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Error(w, "authentication unavailable", http.StatusNotImplemented)
		return
	}
	// Strictly require the local Tauri desktop token so remote/browser callers cannot invoke biometric unlock.
	if s.token != "" && !s.desktopTrusted(r) {
		http.Error(w, "desktop trust required", http.StatusForbidden)
		return
	}
	token, err := s.auth.UnlockWithBiometric()
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

// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/orchestrator"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/tun"
)

// StopTUN disables TUN mode and cleans up any lingering OS routes.
func (s *Server) StopTUN() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	rs := s.runtimeState()
	wasTUN := rs.tunEnabled || s.ensureOrchestrator().Status().TUNEnabled
	s.setTunEnabledState(false)
	if s.store != nil {
		_ = s.store.PutSetting("runtime.tun_enabled", false)
	}
	if s.ensureOrchestrator().Status().Running && wasTUN {
		_, err := s.reconcileRuntime(context.Background(), rs.activeNodeID, rs.activeGroupID, false)
		if runtime.GOOS == "linux" {
			_ = tun.CleanupStaleRoutes(context.Background(), s.effectiveSudoPassword())
		}
		return err
	}
	if wasTUN && runtime.GOOS == "linux" {
		return tun.CleanupStaleRoutes(context.Background(), s.effectiveSudoPassword())
	}
	return nil
}

// ShutdownCleanup stops active cores and cleans OS TUN routes & system proxy on shutdown
// while preserving the user's persisted session state (want_running / tun_enabled / system_proxy_enabled).
func (s *Server) ShutdownCleanup(ctx context.Context) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.androidVPNMu.Lock()
	androidTun := s.androidTun
	s.androidVPNMu.Unlock()
	if androidTun != nil {
		androidTun.Stop()
	}
	s.stopHubAndFlushLedger()
	orch := s.ensureOrchestrator()
	wasTUN := orch.Status().TUNEnabled
	err := orch.Stop()
	if wasTUN && runtime.GOOS == "linux" {
		_ = tun.CleanupStaleRoutes(ctx, s.effectiveSudoPassword())
	}
	if restoreErr := s.RestoreSystemProxy(); restoreErr != nil && err == nil {
		err = restoreErr
	}
	return err
}

func (s *Server) resolvePersistentSingBoxBinary() (string, error) {
	sbBin, err := s.ensureOrchestrator().ResolveSingBoxBinary()
	if err != nil {
		return "", err
	}
	if s.mode != authservice.ModeAndroid && runtime.GOOS != "android" && orchestrator.IsEphemeralMountPath(sbBin) {
		dataDir := ""
		if s.cfg != nil {
			dataDir = s.cfg.DataDir()
		}
		staged, stageErr := orchestrator.StageEphemeralCore(sbBin, dataDir, "sing-box")
		if stageErr != nil {
			return "", fmt.Errorf("无法将 AppImage 内置 sing-box 复制到持久目录：%w", stageErr)
		}
		// Never overwrite core.singbox.active in SQLite with an ephemeral-staged path; otherwise
		// subsequent AppImage / macOS .app upgrades stay pinned to the stale staged binary forever
		// instead of re-staging via StageEphemeralCore's SHA-256 check on next launch.
		s.SetSingBoxPath(staged)
		return staged, nil
	}
	return sbBin, nil
}

func (s *Server) handleTUNPrivilege(w http.ResponseWriter, _ *http.Request) {
	sbBin, _ := s.resolvePersistentSingBoxBinary()
	info := tun.CheckPrivilege(sbBin)
	writeJSON(w, http.StatusOK, map[string]any{
		"os":                     info.OS,
		"singbox_path":           info.SingBoxPath,
		"has_cap_admin":          info.HasCapAdmin,
		"is_root":                info.IsRoot,
		"ready_without_password": info.ReadyWithoutPassword,
		"can_pkexec":             info.CanPkexec,
		"detail":                 info.Detail,
		"sudo_cached":            len(s.effectiveSudoPassword()) > 0,
	})
}

func (s *Server) isManagedSingBoxPath(binPath string) bool {
	realBin, err := filepath.EvalSymlinks(binPath)
	if err != nil {
		realBin = binPath
	}
	realBin, err = filepath.Abs(realBin)
	if err != nil {
		return false
	}
	base := filepath.Base(realBin)
	if base != "sing-box" && !strings.HasPrefix(base, "sing-box-") {
		return false
	}
	allowedRoots := []string{"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/usr/lib/prismray", "/usr/lib/prismray-server"}
	if s.cfg != nil {
		if dd := strings.TrimSpace(s.cfg.DataDir()); dd != "" {
			allowedRoots = append(allowedRoots, dd)
		}
		if rd := strings.TrimSpace(s.cfg.RuntimeDir()); rd != "" {
			allowedRoots = append(allowedRoots, rd)
		}
	}
	if exe, exeErr := os.Executable(); exeErr == nil && exe != "" {
		exeDir := filepath.Dir(exe)
		allowedRoots = append(allowedRoots, exeDir, filepath.Clean(filepath.Join(exeDir, "..", "lib", "prismray")))
	}
	for _, root := range allowedRoots {
		absRoot, rErr := filepath.Abs(root)
		if rErr != nil {
			continue
		}
		if resolvedRoot, symErr := filepath.EvalSymlinks(absRoot); symErr == nil {
			absRoot = resolvedRoot
		}
		rel, relErr := filepath.Rel(absRoot, realBin)
		if relErr == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}

func (s *Server) handleTUNAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sbBin, err := s.resolvePersistentSingBoxBinary()
	if err != nil {
		http.Error(w, "未找到 sing-box 核心："+err.Error(), http.StatusPreconditionFailed)
		return
	}
	if !s.isManagedSingBoxPath(sbBin) {
		http.Error(w, "拒绝为受管目录之外的可执行文件授予网络权限", http.StatusForbidden)
		return
	}
	if err := tun.AuthorizeWithPkexec(r.Context(), sbBin); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	info := tun.CheckPrivilege(sbBin)

	// If TUN was already requested/remembered (e.g. boot fallback started sing-box without TUN
	// before Polkit authorization completed), immediately reconcile runtime with TUN enabled
	// so traffic works right away without requiring the user to switch nodes.
	reconciled := false
	if info.ReadyWithoutPassword && s.mode != authservice.ModeAndroid {
		s.opMu.Lock()
		orch := s.ensureOrchestrator()
		st := orch.Status()
		rs := s.runtimeState()
		shouldEnableTUN := rs.tunEnabled && ((st.Running && !st.TUNEnabled) || (!st.Running && rs.wantRunning))
		if shouldEnableTUN && s.store != nil && len(s.store.List()) > 0 {
			if nextSt, recErr := s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, true); recErr == nil {
				reconciled = nextSt.Running && nextSt.TUNEnabled
				if rs.systemProxyWanted && nextSt.Running && nextSt.MixedPort > 0 && !s.proxyManager().Active() {
					_ = s.proxyManager().Enable(nextSt.MixedPort)
				}
			} else {
				orch.AppendLog("tun", "warn", "TUN 授权后自动重载失败: "+recErr.Error())
			}
		}
		s.opMu.Unlock()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"os":                     info.OS,
		"singbox_path":           info.SingBoxPath,
		"has_cap_admin":          info.HasCapAdmin,
		"is_root":                info.IsRoot,
		"ready_without_password": info.ReadyWithoutPassword,
		"can_pkexec":             info.CanPkexec,
		"detail":                 info.Detail,
		"reconciled":             reconciled,
		"sudo_cached":            len(s.effectiveSudoPassword()) > 0,
	})
}

func (s *Server) handleTUN(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		sbBin, _ := s.resolvePersistentSingBoxBinary()
		priv := tun.CheckPrivilege(sbBin)
		st := s.ensureOrchestrator().Status()
		rs := s.runtimeState()
		stack := rs.tunStack
		if stack == "" {
			if runtime.GOOS == "linux" {
				stack = "mixed"
			} else {
				stack = "gvisor"
			}
		}
		tunActive := st.Running && st.TUNEnabled
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":     tunActive,
			"running":     tunActive,
			"preferred":   rs.tunEnabled,
			"stack":       stack,
			"node_id":     rs.activeNodeID,
			"group_id":    rs.activeGroupID,
			"privilege":   priv,
			"sudo_cached": len(s.effectiveSudoPassword()) > 0,
		})
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool   `json:"enabled"`
		NodeID  string `json:"node_id"`
		GroupID string `json:"group_id"`
		Stack   string `json:"stack"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Stack != "" {
		switch strings.ToLower(strings.TrimSpace(req.Stack)) {
		case "system", "gvisor", "mixed":
			stack := strings.ToLower(strings.TrimSpace(req.Stack))
			s.setTunStackState(stack)
			if s.store != nil {
				_ = s.store.PutSetting("runtime.tun_stack", stack)
			}
		default:
			http.Error(w, "TUN stack must be system, gvisor, or mixed", http.StatusBadRequest)
			return
		}
	}

	if !req.Enabled {
		if err := s.StopTUN(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	if (runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows") && s.mode != authservice.ModeAndroid {
		sbBin, _ := s.resolvePersistentSingBoxBinary()
		priv := tun.CheckPrivilege(sbBin)
		if !priv.ReadyWithoutPassword && len(s.effectiveSudoPassword()) == 0 {
			switch runtime.GOOS {
			case "darwin":
				http.Error(w, "macOS 启用 TUN 前，请先点击授权管理员权限或缓存 sudo 密码", http.StatusPreconditionRequired)
			case "windows":
				http.Error(w, "Windows 开启 TUN (Wintun) 需要管理员权限，请右键 PrismRay 选择「以管理员身份运行」", http.StatusPreconditionRequired)
			default:
				http.Error(w, "启用 TUN 前，请先授权 cap_net_admin 或缓存 sudo 密码", http.StatusPreconditionRequired)
			}
			return
		}
	}

	rs := s.runtimeState()
	targetNodeID := strings.TrimSpace(req.NodeID)
	targetGroupID := strings.TrimSpace(req.GroupID)
	if targetNodeID == "" && targetGroupID == "" {
		targetNodeID = rs.activeNodeID
		targetGroupID = rs.activeGroupID
	}

	st, err := s.reconcileRuntime(r.Context(), targetNodeID, targetGroupID, true)
	if err != nil {
		respondError(w, err, http.StatusBadGateway)
		return
	}
	rsAfter := s.runtimeState()
	if rsAfter.systemProxyWanted && st.Running && st.MixedPort > 0 && s.mode != authservice.ModeAndroid && !s.proxyManager().Active() {
		_ = s.proxyManager().Enable(st.MixedPort)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  true,
		"node_id":  rsAfter.activeNodeID,
		"group_id": rsAfter.activeGroupID,
	})
}

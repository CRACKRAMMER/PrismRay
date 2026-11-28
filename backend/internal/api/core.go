// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
	sbinstall "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/install"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/install"
)

type cachedCoreMeta struct {
	modTime int64
	size    int64
	version string
	unified bool
}

var (
	coreMetaCacheMu sync.Mutex
	coreMetaCache   = map[string]cachedCoreMeta{}
)

func detectCoreVersionInfo(binPath string) (version string, unified bool) {
	binPath = strings.TrimSpace(binPath)
	if binPath == "" {
		return "", false
	}
	st, err := os.Stat(binPath)
	if err != nil || st.IsDir() {
		return "", false
	}
	coreMetaCacheMu.Lock()
	if cached, ok := coreMetaCache[binPath]; ok && cached.modTime == st.ModTime().UnixNano() && cached.size == st.Size() {
		coreMetaCacheMu.Unlock()
		return cached.version, cached.unified
	}
	coreMetaCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, binPath, "version").CombinedOutput()
	text := string(out)
	if strings.Contains(text, "(prismray-core)") {
		unified = true
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if strings.HasPrefix(line, "sing-box version ") && len(fields) >= 3 {
			version = fields[2]
			break
		}
		if strings.HasPrefix(line, "Xray ") && len(fields) >= 2 {
			version = fields[1]
			break
		}
	}

	coreMetaCacheMu.Lock()
	coreMetaCache[binPath] = cachedCoreMeta{
		modTime: st.ModTime().UnixNano(),
		size:    st.Size(),
		version: version,
		unified: unified,
	}
	coreMetaCacheMu.Unlock()
	return version, unified
}

func (s *Server) isAndroidBundledCoreMode() bool {
	return s.mode == authservice.ModeAndroid || runtime.GOOS == "android" || strings.TrimSpace(os.Getenv("PRISMRAY_NATIVE_LIB_DIR")) != ""
}

type coreUpdateSettings struct {
	Xray    bool `json:"xray"`
	SingBox bool `json:"sing_box"`
}

func executableFile(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && (runtime.GOOS == "windows" || info.Mode()&0111 != 0)
}

func (s *Server) handleEnsureCores(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.coreMu.Lock()
	defer s.coreMu.Unlock()
	s.opMu.Lock()
	defer s.opMu.Unlock()

	orch := s.ensureOrchestrator()
	result := map[string]any{}

	if s.isAndroidBundledCoreMode() {
		sbPath, _ := orch.ResolveSingBoxBinary()
		xrayPath, _ := orch.ResolveXrayBinary()
		writeJSON(w, http.StatusOK, map[string]any{
			"managed_by_apk":  true,
			"sing_box_binary": sbPath,
			"xray_binary":     xrayPath,
		})
		return
	}

	sbPath, sbErr := orch.ResolveSingBoxBinary()
	if sbErr != nil || !executableFile(sbPath) {
		version, binary, err := s.installCore(r.Context(), "sing-box", "latest", true)
		if err != nil {
			result["sing_box_error"] = err.Error()
		} else {
			result["sing_box_installed"] = version
			result["sing_box_binary"] = binary
		}
	} else {
		result["sing_box_binary"] = sbPath
	}

	xrayPath, xrayErr := orch.ResolveXrayBinary()
	if xrayErr != nil || !executableFile(xrayPath) {
		version, binary, err := s.installCore(r.Context(), "xray", "latest", true)
		if err != nil {
			result["xray_error"] = err.Error()
		} else {
			result["xray_installed"] = version
			result["xray_binary"] = binary
		}
	} else {
		result["xray_binary"] = xrayPath
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) latestCoreVersion(ctx context.Context, repository string) (string, error) {
	lookup := func(client *http.Client) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+repository+"/releases/latest", nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "PrismRay/"+AppVersion)
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("release lookup failed: %s", resp.Status)
		}
		var release struct {
			TagName string `json:"tag_name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
			return "", err
		}
		return release.TagName, nil
	}
	direct := s.safeHTTPClient(10 * time.Second)
	defer closeClientIdleConnections(direct)
	ver, err := lookup(direct)
	if err != nil {
		if st := s.ensureOrchestrator().Status(); st.Running && st.MixedPort > 0 {
			proxied := s.safeProxyHTTPClient(12*time.Second, st.MixedPort)
			defer closeClientIdleConnections(proxied)
			if pVer, pErr := lookup(proxied); pErr == nil {
				return pVer, nil
			}
		}
	}
	return ver, err
}

func (s *Server) maintainCoreUpdates(ctx context.Context) {
	if s.isAndroidBundledCoreMode() || s.isVaultLocked() {
		return
	}
	s.coreMu.Lock()
	defer s.coreMu.Unlock()
	if !s.lastCoreCheck.IsZero() && time.Since(s.lastCoreCheck) < 24*time.Hour {
		return
	}
	s.lastCoreCheck = time.Now()
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if s.ensureOrchestrator().Status().Running {
		return
	}
	settings := s.updateSettings()
	if settings.SingBox {
		// Never overwrite PrismRay's unified sing-box wrapper with upstream SagerNet/sing-box,
		// which lacks PRISMRAY_CORE_CTRL_ADDR / PRISMRAY_TAILSCALE_STATUS_PATH.
		if _, isUnified := detectCoreVersionInfo(s.SingBoxBinary()); !isUnified {
			if version, err := s.latestCoreVersion(ctx, "SagerNet/sing-box"); err == nil && version != "" {
				if _, _, err := s.installCore(ctx, "sing-box", version, true); err == nil {
					s.lastCoreCheck = time.Now()
				}
			}
		}
	}
	if settings.Xray {
		if version, err := s.latestCoreVersion(ctx, "XTLS/Xray-core"); err == nil && version != "" {
			if _, _, err := s.installCore(ctx, "xray", version, true); err == nil {
				s.lastCoreCheck = time.Now()
			}
		}
	}
}

func (s *Server) coreDir(name string) string {
	base := ""
	if s.cfg != nil {
		base = s.cfg.RuntimeDir()
	}
	if base == "" && s.store != nil {
		base = filepath.Dir(s.store.Path())
	}
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "cores", name)
}

func installedVersions(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	versions := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}
	slices.Sort(versions)
	slices.Reverse(versions)
	return versions, nil
}

func (s *Server) updateSettings() coreUpdateSettings {
	v := coreUpdateSettings{
		Xray:    s.cfg != nil && s.cfg.Xray.AutoUpdate,
		SingBox: s.cfg != nil && s.cfg.SingBox.AutoUpdate,
	}
	if s.store != nil {
		_, _ = s.store.GetSetting("core.auto_update", &v)
	}
	return v
}

func (s *Server) handleCores(w http.ResponseWriter, r *http.Request) {
	orch := s.ensureOrchestrator()
	if r.Method == http.MethodGet {
		sbPath := strings.TrimSpace(s.SingBoxBinary())
		xrayPath := strings.TrimSpace(s.XrayBinary())
		sbVersions, err := installedVersions(s.coreDir("sing-box"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		xrayVersions, err := installedVersions(s.coreDir("xray"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sbAvail := executableFile(sbPath)
		xrayAvail := executableFile(xrayPath)
		cronet := false
		sbVer := ""
		sbUnified := false
		if sbAvail {
			cronet = sbcfg.CronetAvailable(sbPath)
			sbVer, sbUnified = detectCoreVersionInfo(sbPath)
		}
		xrayVer := ""
		if xrayAvail {
			xrayVer, _ = detectCoreVersionInfo(xrayPath)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"managed_by_apk": s.isAndroidBundledCoreMode(),
			"sing_box": map[string]any{
				"installed":        sbAvail,
				"available":        sbAvail,
				"binary":           sbPath,
				"version":          sbVer,
				"unified":          sbUnified,
				"versions":         sbVersions,
				"cronet_available": cronet,
			},
			"xray": map[string]any{
				"installed": xrayAvail,
				"available": xrayAvail,
				"binary":    xrayPath,
				"version":   xrayVer,
				"versions":  xrayVersions,
			},
			"auto_update": s.updateSettings(),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.coreMu.Lock()
	defer s.coreMu.Unlock()
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if orch.Status().Running {
		http.Error(w, "请先停止代理和 TUN 再更换核心", http.StatusConflict)
		return
	}

	var req struct {
		Core          string              `json:"core"`
		Version       string              `json:"version"`
		Download      bool                `json:"download"`
		ForceUpstream bool                `json:"force_upstream"`
		AutoUpdate    *coreUpdateSettings `json:"auto_update"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.AutoUpdate != nil && s.store != nil {
		_ = s.store.PutSetting("core.auto_update", *req.AutoUpdate)
		if req.Core == "" {
			writeJSON(w, http.StatusOK, map[string]any{"auto_update": *req.AutoUpdate})
			return
		}
	}

	req.Core = strings.ToLower(strings.TrimSpace(req.Core))
	if req.Core != "xray" && req.Core != "sing-box" {
		http.Error(w, "core must be xray or sing-box", http.StatusBadRequest)
		return
	}
	if req.Core == "sing-box" && req.Download && !req.ForceUpstream {
		if _, isUnified := detectCoreVersionInfo(s.SingBoxBinary()); isUnified {
			http.Error(w, "当前已启用 PrismRay 内置 Unified sing-box 包装核（支持 Tailscale 控制面）；下载上游 SagerNet/sing-box 将降级内置 Tailscale 控制功能", http.StatusConflict)
			return
		}
	}

	version, binary, err := s.installCore(r.Context(), req.Core, req.Version, req.Download)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"core":          req.Core,
		"version":       version,
		"active_binary": binary,
	})
}

func (s *Server) installCore(ctx context.Context, name, requested string, download bool) (string, string, error) {
	if s.isAndroidBundledCoreMode() {
		orch := s.ensureOrchestrator()
		if name == "sing-box" {
			bin, err := orch.ResolveSingBoxBinary()
			if err != nil {
				return "", "", fmt.Errorf("Android bundled libsingbox.so not found: %w", err)
			}
			s.SetSingBoxPath(bin)
			if s.store != nil {
				_ = s.store.PutSetting("core.singbox.active", bin)
			}
			return "bundled", bin, nil
		}
		bin, err := orch.ResolveXrayBinary()
		if err != nil {
			return "", "", fmt.Errorf("Android bundled libxray.so not found: %w", err)
		}
		s.SetXrayPath(bin)
		if s.store != nil {
			_ = s.store.PutSetting("core.xray.active", bin)
		}
		return "bundled", bin, nil
	}

	version := strings.TrimSpace(requested)
	if version == "" {
		version = "latest"
	}
	if version != "latest" && !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if version != "latest" && (strings.Contains(version, "/") || strings.Contains(version, "\\") || strings.Contains(version, "..")) {
		return "", "", fmt.Errorf("invalid core version")
	}

	binaryName := name
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	if !download && version != "latest" {
		candidate := filepath.Join(s.coreDir(name), version, binaryName)
		if !executableFile(candidate) {
			return "", "", fmt.Errorf("%s %s is not installed", name, version)
		}
		if name == "xray" {
			s.SetXrayPath(candidate)
			if s.store != nil {
				_ = s.store.PutSetting("core.xray.active", candidate)
			}
		} else {
			s.SetSingBoxPath(candidate)
			if s.store != nil {
				_ = s.store.PutSetting("core.singbox.active", candidate)
			}
		}
		return version, candidate, nil
	}

	if name == "sing-box" {
		if version == "latest" {
			latest, err := s.latestCoreVersion(ctx, "SagerNet/sing-box")
			if err == nil && latest != "" {
				version = latest
			}
		}
		targetDir := filepath.Join(s.coreDir(name), version)
		binary, resolvedVersion, err := sbinstall.Download(ctx, targetDir, version)
		if err != nil {
			if st := s.ensureOrchestrator().Status(); st.Running && st.MixedPort > 0 {
				proxied := s.safeProxyHTTPClient(5*time.Minute, st.MixedPort)
				defer closeClientIdleConnections(proxied)
				if pBin, pVer, pErr := sbinstall.DownloadWithClient(ctx, proxied, targetDir, version); pErr == nil {
					binary, resolvedVersion, err = pBin, pVer, nil
				}
			}
		}
		if err != nil {
			return "", "", err
		}
		s.SetSingBoxPath(binary)
		if s.store != nil {
			_ = s.store.PutSetting("core.singbox.active", binary)
		}
		return resolvedVersion, binary, nil
	}

	if version == "latest" {
		latest, err := s.latestCoreVersion(ctx, "XTLS/Xray-core")
		if err != nil {
			return "", "", err
		}
		version = latest
	}
	targetDir := filepath.Join(s.coreDir(name), version)
	binary, err := install.DownloadXrayVersion(targetDir, version)
	if err != nil {
		if st := s.ensureOrchestrator().Status(); st.Running && st.MixedPort > 0 {
			proxied := s.safeProxyHTTPClient(5*time.Minute, st.MixedPort)
			defer closeClientIdleConnections(proxied)
			if pBin, pErr := install.DownloadXrayVersionWithClient(proxied, targetDir, version); pErr == nil {
				binary, err = pBin, nil
			}
		}
	}
	if err != nil {
		return "", "", err
	}
	s.SetXrayPath(binary)
	if s.store != nil {
		_ = s.store.PutSetting("core.xray.active", binary)
	}
	return version, binary, nil
}

func (s *Server) handleLogExport(w http.ResponseWriter, _ *http.Request) {
	entries := s.ensureOrchestrator().LogHistory(0)
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		lines = append(lines, fmt.Sprintf("[%s] [%s] [%s] %s", e.Timestamp, e.Core, e.Level, e.Message))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="prismray.log"`)
	_, _ = w.Write([]byte(strings.Join(lines, "\n")))
}

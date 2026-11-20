// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/orchestrator"
	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/tun"
)

type httpError struct {
	Code int
	Msg  string
}

func (e *httpError) Error() string { return e.Msg }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func respondError(w http.ResponseWriter, err error, defaultStatus int) {
	if err == nil {
		return
	}
	var he *httpError
	if errors.As(err, &he) && he.Code >= 400 {
		http.Error(w, he.Msg, he.Code)
		return
	}
	if defaultStatus < 400 {
		defaultStatus = http.StatusInternalServerError
	}
	http.Error(w, err.Error(), defaultStatus)
}

func (s *Server) ensureOrchestrator() *orchestrator.Orchestrator {
	s.orchMu.Lock()
	defer s.orchMu.Unlock()
	if s.orch != nil {
		return s.orch
	}
	workDir := ""
	sbBin := s.singBoxBinary
	xrayBin := s.xrayBinary
	if s.cfg != nil {
		workDir = s.cfg.RuntimeDir()
		if sbBin == "" {
			sbBin = s.cfg.SingBox.BinaryPath
		}
		if xrayBin == "" {
			xrayBin = s.cfg.Xray.BinaryPath
		}
	}
	if workDir == "" && s.store != nil {
		workDir = filepath.Dir(s.store.Path())
	}
	if workDir == "" {
		workDir = os.TempDir()
	}
	s.orch = orchestrator.New(orchestrator.Options{
		WorkDir:       workDir,
		SingBoxBinary: sbBin,
		XrayBinary:    xrayBin,
	})
	return s.orch
}

// SetSingBoxPath configures the managed sing-box binary path on both Server and Orchestrator.
func (s *Server) SetSingBoxPath(path string) {
	s.singBoxBinary = path
	if s.cfg != nil {
		s.cfg.SingBox.BinaryPath = path
	}
	s.ensureOrchestrator().SetBinaries(path, "")
}

// SetXrayPath configures the managed Xray coprocessor binary path on Server, legacy PM, and Orchestrator.
func (s *Server) SetXrayPath(path string) {
	s.xrayBinary = path
	if s.pm != nil {
		s.pm.SetBinaryPath(path)
	}
	if s.cfg != nil {
		s.cfg.Xray.BinaryPath = path
	}
	s.ensureOrchestrator().SetBinaries("", path)
}

func (s *Server) ruleSetDir() string {
	dataDir := ""
	if s.cfg != nil {
		dataDir = s.cfg.RuntimeDir()
		if raw := strings.TrimSpace(s.cfg.SingBox.RuleSetDir); raw != "" {
			if filepath.IsAbs(raw) {
				return raw
			}
			if dataDir != "" {
				return filepath.Join(dataDir, raw)
			}
			return raw
		}
	}
	if dataDir == "" && s.store != nil {
		dataDir = filepath.Dir(s.store.Path())
	}
	if dataDir == "" {
		dataDir = os.TempDir()
	}
	return filepath.Join(dataDir, "rulesets")
}

func (s *Server) routingProfile() (ruleset.RoutingProfile, error) {
	profile := ruleset.DefaultRoutingProfile()
	if s.store == nil {
		return profile, nil
	}
	rec, found, err := s.store.GetRoutingProfile("default")
	if err != nil {
		return profile, err
	}
	if !found || len(rec.Document) == 0 {
		return profile, nil
	}
	if err := json.Unmarshal(rec.Document, &profile); err != nil {
		return ruleset.DefaultRoutingProfile(), err
	}
	profile.Normalize()
	return profile, nil
}

func (s *Server) saveRoutingProfile(profile ruleset.RoutingProfile) error {
	profile.Normalize()
	raw, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	if s.store == nil {
		return nil
	}
	return s.store.SaveRoutingProfile(storage.RoutingProfileRecord{
		ID:       "default",
		Document: raw,
	})
}

func (s *Server) effectiveRuleSets() ([]ruleset.RuleSetSpec, error) {
	builtins := ruleset.BuiltinRuleSets(s.ruleSetDir())
	byID := make(map[string]int, len(builtins))
	out := make([]ruleset.RuleSetSpec, len(builtins))
	for i, spec := range builtins {
		if info, err := os.Stat(spec.LocalPath); err == nil && !info.IsDir() && info.Size() > 0 {
			spec.Synced = true
			spec.SizeBytes = info.Size()
		}
		out[i] = spec
		byID[spec.ID] = i
	}
	if s.store == nil {
		return out, nil
	}
	stored, err := s.store.ListRuleSets()
	if err != nil {
		return nil, err
	}
	for _, r := range stored {
		spec := ruleset.RuleSetSpec{
			ID:             r.ID,
			Tag:            r.Tag,
			Format:         r.Format,
			SourceType:     r.SourceType,
			URL:            r.URL,
			LocalPath:      r.LocalPath,
			UpdateInterval: r.UpdateInterval,
			Enabled:        r.Enabled,
			SizeBytes:      r.SizeBytes,
			LastSyncedAt:   r.LastSyncedAt,
		}
		if spec.LocalPath == "" && spec.SourceType == "remote" {
			spec.LocalPath = filepath.Join(s.ruleSetDir(), spec.Tag+".srs")
		}
		if spec.LocalPath != "" {
			if info, statErr := os.Stat(spec.LocalPath); statErr == nil && !info.IsDir() && info.Size() > 0 {
				spec.Synced = true
				spec.SizeBytes = info.Size()
			}
		}
		if idx, ok := byID[spec.ID]; ok {
			out[idx] = spec
		} else {
			byID[spec.ID] = len(out)
			out = append(out, spec)
		}
	}
	return out, nil
}

func (s *Server) effectiveSudoPassword() []byte {
	if s.store == nil {
		return nil
	}
	pass, ok, err := s.store.GetSecret("security.sudo_password")
	if err != nil || !ok || len(pass) == 0 {
		return nil
	}
	return pass
}

func (s *Server) persistRuntimeSelection(nodeID, groupID string, tunEnabled bool) {
	s.activeNodeID = nodeID
	s.activeGroupID = groupID
	s.tunEnabled = tunEnabled
	if s.store == nil {
		return
	}
	_ = s.store.PutSetting("runtime.active_node_id", nodeID)
	_ = s.store.PutSetting("runtime.active_group_id", groupID)
	_ = s.store.PutSetting("runtime.tun_enabled", tunEnabled)
}

func (s *Server) persistWantRunning(want bool) {
	s.wantRunning = want
	if s.store != nil {
		_ = s.store.PutSetting("runtime.want_running", want)
	}
}

func (s *Server) persistSystemProxyWanted(want bool) {
	s.systemProxyWanted = want
	if s.store != nil {
		_ = s.store.PutSetting("runtime.system_proxy_enabled", want)
	}
}

// RestoreLastSession reconnects runtime, TUN, and system proxy if they were active before the last shutdown.
func (s *Server) RestoreLastSession(ctx context.Context) {
	if s.store == nil {
		return
	}
	if s.auth != nil {
		initialized, unlocked := s.auth.Status()
		if !initialized || !unlocked {
			return
		}
	}
	s.opMu.Lock()
	want := s.wantRunning
	wantTUN := s.tunEnabled
	wantSys := s.systemProxyWanted
	nodeID := s.activeNodeID
	groupID := s.activeGroupID
	orch := s.ensureOrchestrator()
	alreadyRunning := orch.Status().Running
	s.opMu.Unlock()

	if !want || alreadyRunning {
		return
	}
	if len(s.store.List()) == 0 {
		return
	}

	effectiveTUN := wantTUN
	if effectiveTUN && (runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows") && s.mode != authservice.ModeAndroid {
		sbBin, _ := s.resolvePersistentSingBoxBinary()
		if !tun.CheckPrivilege(sbBin).ReadyWithoutPassword && len(s.effectiveSudoPassword()) == 0 {
			effectiveTUN = false
			orch.AppendLog("system", "warn", "启动恢复：TUN 缺少免密权限，保留 TUN 偏好并先以普通模式恢复连接")
		}
	}

	s.opMu.Lock()
	st, err := s.reconcileRuntime(ctx, nodeID, groupID, effectiveTUN)
	if err == nil && wantTUN && !effectiveTUN {
		s.persistRuntimeSelection(s.activeNodeID, s.activeGroupID, true)
	}
	s.opMu.Unlock()

	if err != nil {
		orch.AppendLog("system", "warn", "启动恢复上次连接失败: "+err.Error())
		return
	}
	if wantSys && st.Running && st.MixedPort > 0 && s.mode != authservice.ModeAndroid {
		m := s.proxyManager()
		if !m.Active() {
			if spErr := m.Enable(st.MixedPort); spErr != nil {
				orch.AppendLog("system", "warn", "启动恢复系统代理失败: "+spErr.Error())
			}
		}
	}
}

func (s *Server) effectiveProtectPath() string {
	p := strings.TrimSpace(s.protectPath)
	if p == "" {
		return ""
	}
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

func (s *Server) androidRuntimeSettings() (bool, string) {
	p := s.effectiveProtectPath()
	if s.mode == authservice.ModeAndroid {
		return true, p
	}
	return p != "", p
}

// reconcileRuntime compiles the desired v1.0 runtime snapshot and delegates lifecycle
// orchestration to Orchestrator. Caller must hold s.opMu.
func (s *Server) reconcileRuntime(ctx context.Context, activeNodeID, activeGroupID string, enableTUN bool) (orchestrator.Status, error) {
	orch := s.ensureOrchestrator()
	androidMode, protectPath := s.androidRuntimeSettings()

	if enableTUN && runtime.GOOS == "linux" && !androidMode {
		sbBin, _ := orch.ResolveSingBoxBinary()
		priv := tun.CheckPrivilege(sbBin)
		sudoPass := s.effectiveSudoPassword()
		if !priv.ReadyWithoutPassword && len(sudoPass) == 0 {
			return orch.Status(), &httpError{
				Code: http.StatusPreconditionRequired,
				Msg:  "启用 TUN 前，请先在设置中授予 cap_net_admin 权限或验证保存 sudo 密码",
			}
		}
	}

	nodes := s.store.List()
	if len(nodes) == 0 {
		return orch.Status(), &httpError{Code: http.StatusBadRequest, Msg: "请先添加至少一个代理节点"}
	}
	groups, err := s.store.ListGroups()
	if err != nil {
		return orch.Status(), err
	}

	if activeNodeID != "" {
		found := false
		for _, n := range nodes {
			if n.ID == activeNodeID {
				found = true
				break
			}
		}
		if !found {
			return orch.Status(), &httpError{Code: http.StatusBadRequest, Msg: "node not found"}
		}
	}
	if activeGroupID != "" {
		found := false
		for _, g := range groups {
			if g.ID == activeGroupID {
				found = true
				break
			}
		}
		if !found {
			return orch.Status(), &httpError{Code: http.StatusBadRequest, Msg: "group not found"}
		}
	}
	if activeNodeID == "" && activeGroupID == "" {
		if len(groups) > 0 {
			activeGroupID = groups[0].ID
		} else {
			activeNodeID = nodes[0].ID
		}
	}

	listeners := s.store.ListListeners()
	routing, err := s.routingProfile()
	if err != nil {
		return orch.Status(), err
	}
	ruleSets, err := s.effectiveRuleSets()
	if err != nil {
		return orch.Status(), err
	}

	var sudoPass []byte
	if enableTUN && (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !androidMode {
		sbBin, _ := orch.ResolveSingBoxBinary()
		if !tun.CheckPrivilege(sbBin).ReadyWithoutPassword {
			sudoPass = s.effectiveSudoPassword()
		}
	}

	mixedPort := 10808
	clashPort := 0
	clashSecret := ""
	if s.cfg != nil {
		if s.cfg.SingBox.MixedPort > 0 {
			mixedPort = s.cfg.SingBox.MixedPort
		} else {
			mixedPort = 0
		}
		clashPort = s.cfg.SingBox.ClashAPIPort
		clashSecret = s.cfg.SingBox.ClashAPISecret
	}

	in := orchestrator.ApplyInput{
		Nodes:          nodes,
		Groups:         groups,
		Listeners:      listeners,
		Routing:        routing,
		RuleSets:       ruleSets,
		ActiveNodeID:   activeNodeID,
		ActiveGroupID:  activeGroupID,
		MixedPort:      mixedPort,
		ClashAPIPort:   clashPort,
		ClashAPISecret: clashSecret,
		EnableTUN:      enableTUN,
		TUNStack:       s.tunStack,
		AndroidMode:    androidMode,
		ProtectPath:    protectPath,
		SudoPassword:   sudoPass,
	}

	st, err := orch.Apply(ctx, in)
	if err != nil {
		return st, &httpError{Code: http.StatusBadGateway, Msg: err.Error()}
	}
	s.persistRuntimeSelection(activeNodeID, activeGroupID, enableTUN)
	s.persistWantRunning(true)
	if st.ActiveTag != "" && st.ActiveTag != sbcfg.BlockOutboundTag {
		s.setKillSwitchBaseline(st.ActiveTag)
	} else if routing.KillSwitchEnabled() && routing.Mode != "direct" && st.ActiveTag == sbcfg.BlockOutboundTag {
		s.setKillSwitchTripped("", "无可用代理节点，Kill Switch 已阻断代理流量防止直连泄漏")
	} else {
		s.clearKillSwitch()
	}
	return st, nil
}

func (s *Server) validateCandidateNode(n *config.Node) error {
	if n == nil {
		return &httpError{Code: http.StatusBadRequest, Msg: "node is required"}
	}
	if err := n.Validate(); err != nil {
		return &httpError{Code: http.StatusBadRequest, Msg: err.Error()}
	}
	return nil
}

// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/fileutil"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/clashapi"
	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/tun"
	xraycfg "github.com/CRACKRAMMER/PrismRay/backend/internal/xray/config"
)

const (
	defaultLogCapacity = 2000
	defaultReadyWait   = 6 * time.Second
	probeConcurrency   = 16
)

// Options configures a dual-core Orchestrator instance.
type Options struct {
	WorkDir       string
	SingBoxBinary string
	XrayBinary    string
	LogCapacity   int
	ReadyTimeout  time.Duration
}

// ApplyInput captures the complete runtime snapshot compiled and reconciled by the Orchestrator.
type ApplyInput struct {
	Nodes               []*config.Node
	Groups              []storage.Group
	Listeners           []*config.ListenConfig
	Routing             ruleset.RoutingProfile
	RuleSets            []ruleset.RuleSetSpec
	ActiveNodeID        string
	ActiveGroupID       string
	MixedPort           int
	ClashAPIPort        int
	ClashAPISecret      string
	EnableTUN           bool
	TUNStack            string
	AndroidMode         bool
	ProtectPath         string
	AndroidNetIfPath    string
	SudoPassword        []byte
	HighLatencyMS       int
	Tailscale           *ruleset.TailscaleConfig
	TailscaleStateDir   string
	TailscaleStatusPath string
}

// Status summarizes the live state of sing-box and the on-demand Xray coprocessor.
type Status struct {
	Running         bool     `json:"running"`
	SingBoxRunning  bool     `json:"singbox_running"`
	XrayRunning     bool     `json:"xray_running"`
	SingBoxPID      int      `json:"singbox_pid,omitempty"`
	XrayPID         int      `json:"xray_pid,omitempty"`
	ActiveNodeID    string   `json:"active_node_id,omitempty"`
	ActiveGroupID   string   `json:"active_group_id,omitempty"`
	ActiveTag       string   `json:"active_tag,omitempty"`
	TUNEnabled      bool     `json:"tun_enabled"`
	AndroidMode     bool     `json:"android_mode"`
	MixedPort       int      `json:"mixed_port,omitempty"`
	AppSocksPort    int      `json:"-"`
	AppSocksSecret  string   `json:"-"`
	AppPackages     []string `json:"-"`
	ClashAPIPort    int      `json:"clash_api_port,omitempty"`
	UptimeSeconds   int64    `json:"uptime_seconds,omitempty"`
	LastError       string   `json:"last_error,omitempty"`
	SkippedNaive    []string `json:"skipped_naive,omitempty"`
	ResolvedSingBox string   `json:"resolved_singbox,omitempty"`
	ResolvedXray    string   `json:"resolved_xray,omitempty"`
}

// LogEntry represents a redacted structured log record from sing-box, Xray, or the orchestrator.
type LogEntry struct {
	Seq       uint64 `json:"seq"`
	Timestamp string `json:"timestamp"`
	Core      string `json:"core"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

const (
	defaultSpeedDownURL = "https://speed.cloudflare.com/__down?bytes=10000000"
	defaultSpeedUpURL   = "https://speed.cloudflare.com/__up"
	speedBatchSize      = 8
	speedConcurrency    = 2
)

// ProbeOptions configures node probing across TCP ping, real-connection URL delay, and throughput tests.
type ProbeOptions struct {
	Mode         string // "urltest" (default) | "ping" | "speed" | "full"
	TestURL      string
	SpeedDownURL string
	SpeedUpURL   string
	LocalDNS     string
	AndroidMode  bool
	ProtectPath  string
	Timeout      time.Duration
	AllNodes     []*config.Node
	AllGroups    []storage.Group
}

func expandDetourDependencies(targets []*config.Node, allNodes []*config.Node, allGroups []storage.Group) ([]*config.Node, []storage.Group) {
	if len(allNodes) == 0 && len(allGroups) == 0 {
		return targets, nil
	}
	nodeByID := make(map[string]*config.Node, len(allNodes)+len(targets))
	for _, n := range allNodes {
		if n != nil && n.ID != "" {
			nodeByID[n.ID] = n
		}
	}
	for _, n := range targets {
		if n != nil && n.ID != "" {
			nodeByID[n.ID] = n
		}
	}
	groupByID := make(map[string]storage.Group, len(allGroups))
	for _, g := range allGroups {
		if g.ID != "" {
			groupByID[g.ID] = g
		}
	}

	includedNodes := make([]*config.Node, 0, len(targets))
	seenNode := make(map[string]bool, len(targets))
	includedGroups := []storage.Group{}
	seenGroup := map[string]bool{}

	var addNode func(n *config.Node, depth int)
	var addGroup func(g storage.Group, depth int)
	addGroup = func(g storage.Group, depth int) {
		if g.ID == "" || seenGroup[g.ID] || depth > 8 {
			return
		}
		seenGroup[g.ID] = true
		includedGroups = append(includedGroups, g)
		if gDetour := strings.TrimSpace(g.DetourID); gDetour != "" {
			if rg, ok := groupByID[gDetour]; ok {
				addGroup(rg, depth+1)
			} else if rn := nodeByID[gDetour]; rn != nil && rn.Validate() == nil {
				addNode(rn, depth+1)
			}
		}
		for _, mid := range g.NodeIDs {
			if m := nodeByID[mid]; m != nil && m.Validate() == nil {
				addNode(m, depth+1)
			}
		}
	}
	addNode = func(n *config.Node, depth int) {
		if n == nil || n.ID == "" || seenNode[n.ID] || depth > 8 {
			return
		}
		seenNode[n.ID] = true
		includedNodes = append(includedNodes, n)
		detourID := strings.TrimSpace(n.DetourID)
		if detourID == "" {
			return
		}
		if g, ok := groupByID[detourID]; ok {
			addGroup(g, depth+1)
		} else if relay := nodeByID[detourID]; relay != nil && relay.Validate() == nil {
			addNode(relay, depth+1)
		}
	}

	for _, n := range targets {
		addNode(n, 0)
	}
	return includedNodes, includedGroups
}

type stderrTail struct {
	mu    sync.Mutex
	lines []string
}

func (t *stderrTail) Add(line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, trimmed)
	if len(t.lines) > 8 {
		t.lines = t.lines[len(t.lines)-8:]
	}
}

func (t *stderrTail) Summary(redact func(string) string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.lines) == 0 {
		return ""
	}
	joined := strings.Join(t.lines, " | ")
	if redact != nil {
		joined = redact(joined)
	}
	return joined
}

// ProbeResult represents the latency, TCP ping, and bandwidth result for one node.
type ProbeResult struct {
	NodeID        string  `json:"node_id"`
	LatencyMS     int64   `json:"latency_ms"`
	PingMS        int64   `json:"ping_ms,omitempty"`
	DownSpeedMbps float64 `json:"down_speed_mbps,omitempty"`
	UpSpeedMbps   float64 `json:"up_speed_mbps,omitempty"`
	Mode          string  `json:"mode,omitempty"`
	Error         string  `json:"error,omitempty"`
}

type managedProc struct {
	core     string
	cmd      *exec.Cmd
	pid      int
	doneCh   chan error
	sudoPass []byte
}

// Orchestrator coordinates sing-box (primary network plane) and Xray v26 (on-demand coprocessor).
type Orchestrator struct {
	opMu sync.Mutex
	mu   sync.RWMutex

	workDir       string
	singBoxBinary string
	xrayBinary    string
	readyTimeout  time.Duration

	singBoxProc *managedProc
	xrayProc    *managedProc

	running              bool
	startedAt            time.Time
	stopping             bool
	topologyHash         string
	includedTags         map[string]bool
	groupSelections      map[string]string
	lbShardTargets       map[string][]string
	activeNodeID         string
	activeGroupID        string
	activeTag            string
	tunEnabled           bool
	androidMode          bool
	mixedPort            int
	appSocksPort         int
	appSocksSecret       string
	appPackages          []string
	clashAPIPort         int
	clashAPISecret       string
	clash                *clashapi.Client
	coreCtrlAddr         string
	coreCtrlToken        string
	tailscaleStatusToken string
	skippedNaive         []string
	lastError            string
	resolvedSB           string
	resolvedXray         string

	// Redacted structured log ring buffer + pub/sub
	logMu             sync.Mutex
	logs              []LogEntry
	logHead           int
	logCount          int
	logSeq            atomic.Uint64
	subscribers       map[uint64]chan LogEntry
	subSeq            atomic.Uint64
	secretsMu         sync.RWMutex
	secrets           []string
	secretReplacer    atomic.Pointer[strings.Replacer]
	failHandlerMu     sync.RWMutex
	onOutboundFailure func(outboundTag, errLine string)
	failThrottleMu    sync.Mutex
	lastFailEmit      map[string]time.Time

	tsStatusMu   sync.RWMutex
	tsAuthURL    string
	tsLastError  string
	tsUpdatedAt  time.Time
	tsStatusPath string
}

// CoreControlEndpoint returns the authenticated local control-plane address and token
// for PrismRay's unified sing-box wrapper (used for live Tailscale Exit Node / Ping / Logout / Taildrop).
func (o *Orchestrator) CoreControlEndpoint() (addr, token string) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if !o.running {
		return "", ""
	}
	return o.coreCtrlAddr, o.coreCtrlToken
}

// TailscaleStatusToken returns the per-launch token embedded in tailscale-status.json so
// sudo-elevated TUN launches match live Tailscale snapshots reliably even when sbProc.pid is sudo's PID.
func (o *Orchestrator) TailscaleStatusToken() string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if !o.running {
		return ""
	}
	return o.tailscaleStatusToken
}

// TailscaleLogTelemetry returns the latest Tailscale authentication URL and error extracted from sing-box logs.
func (o *Orchestrator) TailscaleLogTelemetry() (authURL, lastError string, updatedAt time.Time) {
	o.tsStatusMu.RLock()
	defer o.tsStatusMu.RUnlock()
	return o.tsAuthURL, o.tsLastError, o.tsUpdatedAt
}

func (o *Orchestrator) resetTailscaleTelemetry(statusPath string) {
	o.tsStatusMu.Lock()
	prevPath := o.tsStatusPath
	o.tsAuthURL = ""
	o.tsLastError = ""
	o.tsUpdatedAt = time.Time{}
	o.tsStatusPath = strings.TrimSpace(statusPath)
	o.tsStatusMu.Unlock()
	if prevPath != "" {
		_ = os.Remove(prevPath)
	}
	if statusPath != "" && statusPath != prevPath {
		_ = os.Remove(statusPath)
	}
}

// SetOutboundFailureHandler registers an asynchronous callback notified when sing-box logs
// a connection/dial failure on a node outbound (used for zero-idle-cost reactive fast failover).
func (o *Orchestrator) SetOutboundFailureHandler(fn func(outboundTag, errLine string)) {
	o.failHandlerMu.Lock()
	o.onOutboundFailure = fn
	o.failHandlerMu.Unlock()
}

// New constructs a new Orchestrator.
func New(opts Options) *Orchestrator {
	workDir := strings.TrimSpace(opts.WorkDir)
	if workDir == "" {
		workDir = os.TempDir()
	}
	logCap := opts.LogCapacity
	if logCap <= 0 {
		logCap = defaultLogCapacity
	}
	readyTimeout := opts.ReadyTimeout
	if readyTimeout <= 0 {
		readyTimeout = defaultReadyWait
	}
	return &Orchestrator{
		workDir:         workDir,
		singBoxBinary:   strings.TrimSpace(opts.SingBoxBinary),
		xrayBinary:      strings.TrimSpace(opts.XrayBinary),
		readyTimeout:    readyTimeout,
		includedTags:    map[string]bool{},
		groupSelections: map[string]string{},
		logs:            make([]LogEntry, logCap),
		subscribers:     make(map[uint64]chan LogEntry),
	}
}

// SetBinaries overrides configured sing-box and Xray binary paths.
func (o *Orchestrator) SetBinaries(singBoxPath, xrayPath string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if s := strings.TrimSpace(singBoxPath); s != "" {
		o.singBoxBinary = s
	}
	if x := strings.TrimSpace(xrayPath); x != "" {
		o.xrayBinary = x
	}
}

// ResolveSingBoxBinary locates the sing-box executable across configured paths,
// Android nativeLibraryDir, executable sidecars, development cores, and PATH.
func (o *Orchestrator) ResolveSingBoxBinary() (string, error) {
	o.mu.RLock()
	configured := o.singBoxBinary
	o.mu.RUnlock()
	return ResolveBinary("sing-box", configured, "PRISMRAY_SINGBOX_BINARY", "libsingbox.so")
}

// ResolveXrayBinary locates the Xray executable across configured paths,
// Android nativeLibraryDir, executable sidecars, development cores, and PATH.
func (o *Orchestrator) ResolveXrayBinary() (string, error) {
	o.mu.RLock()
	configured := o.xrayBinary
	o.mu.RUnlock()
	return ResolveBinary("xray", configured, "PRISMRAY_XRAY_BINARY", "libxray.so")
}

// ResolveBinary finds a core executable across standard deployment layouts.
func ResolveBinary(name, configured, envVar, androidSOName string) (string, error) {
	checkFile := func(p string) (string, bool) {
		p = strings.TrimSpace(p)
		if p == "" {
			return "", false
		}
		abs, err := filepath.Abs(p)
		if err == nil {
			p = abs
		}
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			return "", false
		}
		return p, true
	}

	// On Android (API 29+ W^X SELinux), only binaries packaged in nativeLibraryDir
	// are executable; always prioritize PRISMRAY_NATIVE_LIB_DIR over stale data-dir paths.
	if nativeDir := strings.TrimSpace(os.Getenv("PRISMRAY_NATIVE_LIB_DIR")); nativeDir != "" && androidSOName != "" {
		if p, ok := checkFile(filepath.Join(nativeDir, androidSOName)); ok {
			return p, nil
		}
	}
	if configured != "" {
		if p, ok := checkFile(configured); ok {
			return p, nil
		}
	}
	if envVar != "" {
		if p, ok := checkFile(os.Getenv(envVar)); ok {
			return p, nil
		}
	}

	var dirs []string
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		dirs = append(dirs, exeDir, filepath.Join(exeDir, "binaries"), filepath.Join(exeDir, "cores"))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd, filepath.Join(cwd, "cores"), filepath.Join(cwd, "backend", "cores"))
	}
	if runtime.GOOS == "linux" {
		dirs = append(dirs, "/usr/lib/prismray-server", "/usr/lib/prismray")
	}

	candidates := []string{name}
	if runtime.GOOS == "windows" {
		candidates = append([]string{name + ".exe"}, candidates...)
	}
	for _, dir := range dirs {
		for _, c := range candidates {
			if p, ok := checkFile(filepath.Join(dir, c)); ok {
				return p, nil
			}
		}
		// Match versioned dev bundles like backend/cores/<name>/v*/<name>
		pattern := filepath.Join(dir, name, "*", name)
		if runtime.GOOS == "windows" {
			pattern += ".exe"
		}
		if matches, err := filepath.Glob(pattern); err == nil && len(matches) > 0 {
			sort.Strings(matches)
			for i := len(matches) - 1; i >= 0; i-- {
				if p, ok := checkFile(matches[i]); ok {
					return p, nil
				}
			}
		}
	}

	if looked, err := exec.LookPath(name); err == nil {
		if p, ok := checkFile(looked); ok {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s binary not found", name)
}

// Apply reconciles the running sing-box + Xray stack to match the supplied configuration snapshot.
// When the underlying topology is unchanged and only ActiveNodeID / ActiveGroupID / group SelectedNodeID
// moved between loaded tags, it performs a zero-interruption Clash API hot-switch without restarting TUN.
func (o *Orchestrator) Apply(ctx context.Context, in ApplyInput) (Status, error) {
	o.opMu.Lock()
	defer o.opMu.Unlock()

	o.registerSecrets(in)

	if in.MixedPort <= 0 {
		in.MixedPort = 10808
	}
	sbBin, err := o.ResolveSingBoxBinary()
	if err != nil {
		o.setLastError(err.Error())
		return o.Status(), err
	}
	includeNaive := sbcfg.CronetAvailable(sbBin)

	topoHash, err := topologyFingerprint(in, includeNaive)
	if err != nil {
		return o.Status(), err
	}

	// Zero-interruption Clash API hot-switch path when already running & topology matches.
	if o.tryHotSwitch(ctx, in, topoHash) {
		return o.Status(), nil
	}

	if in.ClashAPIPort <= 0 {
		p, err := freePort()
		if err != nil {
			o.setLastError(err.Error())
			return o.Status(), err
		}
		in.ClashAPIPort = p
	}
	if strings.TrimSpace(in.ClashAPISecret) == "" {
		in.ClashAPISecret = randomHexSecret(16)
		o.registerLiteralSecret(in.ClashAPISecret)
	}

	var xrayMark uint32
	if in.EnableTUN && !in.AndroidMode && runtime.GOOS == "linux" {
		xrayMark = sbcfg.LinuxAutoRedirectOutputMark
	}

	// Allocate loopback SOCKS5 bridge ports for Xray-exclusive nodes.
	var xraySpecs []xraycfg.BridgeSpec
	bridgePorts := map[string]int{}
	for _, n := range in.Nodes {
		if n == nil || n.ID == "" || !n.RequiresXray() {
			continue
		}
		if n.Protocol == config.ProtocolNaive && !includeNaive {
			continue
		}
		port, err := freePort()
		if err != nil {
			o.setLastError(err.Error())
			return o.Status(), err
		}
		bridgePorts[n.ID] = port
		xraySpecs = append(xraySpecs, xraycfg.BridgeSpec{Node: n, ListenPort: port})
	}

	_ = os.MkdirAll(o.workDir, 0o700)

	var xrayBin string
	var xrayJSON []byte
	var xrayCfgPath string
	var xrayUseSudo bool
	if len(xraySpecs) > 0 {
		xrayBin, err = o.ResolveXrayBinary()
		if err != nil {
			o.setLastError(fmt.Sprintf("Xray coprocessor required by nodes (%d): %v", len(xraySpecs), err))
			return o.Status(), err
		}
		xrayDefaultMark := uint32(0)
		if xrayMark != 0 {
			if tun.HasMarkCapability(xrayBin) {
				xrayDefaultMark = xrayMark
			} else if len(in.SudoPassword) > 0 {
				xrayDefaultMark = xrayMark
				xrayUseSudo = true
			}
		}
		xrayDoc, err := xraycfg.GenerateSidecarConfig(xraySpecs, mapXrayLogLevel(in.Routing.LogLevel), xrayDefaultMark)
		if err != nil {
			o.setLastError(err.Error())
			return o.Status(), err
		}
		xrayJSON, err = xrayDoc.ToJSON()
		if err != nil {
			o.setLastError(err.Error())
			return o.Status(), err
		}
		xrayCfgPath = filepath.Join(o.workDir, "xray-sidecar.json")
		if err := fileutil.WritePrivate(xrayCfgPath, xrayJSON); err != nil {
			o.setLastError(err.Error())
			return o.Status(), err
		}
		if err := runPreflight(ctx, xrayBin, []string{"run", "-test", "-config", xrayCfgPath}); err != nil {
			msg := o.redactString(fmt.Sprintf("xray config check failed: %v", err))
			o.AppendLog("xray", "error", msg)
			o.setLastError(msg)
			return o.Status(), errors.New(msg)
		}
	}

	var appPackages []string
	var appSocksPort int
	var appSocksSecret string
	if in.AndroidMode {
		appPackages = collectAndroidRulePackages(in.Routing)
		if len(appPackages) > 0 {
			p, portErr := freePort()
			if portErr != nil {
				o.setLastError(portErr.Error())
				return o.Status(), portErr
			}
			appSocksPort = p
			appSocksSecret = randomHexSecret(16)
			o.registerLiteralSecret(appSocksSecret)
		}
	}

	if in.Tailscale != nil && in.Tailscale.AuthKey != "" {
		o.registerLiteralSecret(in.Tailscale.AuthKey)
	}
	compiled, err := sbcfg.Compile(sbcfg.CompileInput{
		Nodes:                 in.Nodes,
		Groups:                in.Groups,
		Listeners:             in.Listeners,
		Routing:               in.Routing,
		RuleSets:              in.RuleSets,
		ActiveNodeID:          in.ActiveNodeID,
		ActiveGroupID:         in.ActiveGroupID,
		MixedPort:             in.MixedPort,
		ClashAPIPort:          in.ClashAPIPort,
		ClashAPISecret:        in.ClashAPISecret,
		EnableTUN:             in.EnableTUN,
		TUNStack:              in.TUNStack,
		AndroidMode:           in.AndroidMode,
		ProtectPath:           in.ProtectPath,
		AndroidAppSocksPort:   appSocksPort,
		AndroidAppSocksSecret: appSocksSecret,
		AndroidAppPackages:    appPackages,
		XrayBridgePorts:       bridgePorts,
		IncludeNaive:          includeNaive,
		CacheFilePath:         filepath.Join(o.workDir, "cache.db"),
		HighLatencyMS:         in.HighLatencyMS,
		Tailscale:             in.Tailscale,
		TailscaleStateDir:     in.TailscaleStateDir,
	})
	if err != nil {
		msg := o.redactString(err.Error())
		o.setLastError(msg)
		return o.Status(), errors.New(msg)
	}

	sbCfgPath := filepath.Join(o.workDir, "sing-box.json")
	if err := fileutil.WritePrivate(sbCfgPath, compiled.Raw); err != nil {
		o.setLastError(err.Error())
		return o.Status(), err
	}
	if err := runPreflight(ctx, sbBin, []string{"check", "-c", sbCfgPath}); err != nil {
		msg := o.redactString(fmt.Sprintf("sing-box config check failed: %v", err))
		o.AppendLog("sing-box", "error", msg)
		o.setLastError(msg)
		return o.Status(), errors.New(msg)
	}

	// Preflight succeeded; tear down any currently running processes cleanly before starting the new topology.
	o.stopLocked()
	if in.Tailscale != nil && in.Tailscale.Enabled {
		o.resetTailscaleTelemetry(in.TailscaleStatusPath)
	} else {
		o.resetTailscaleTelemetry("")
	}

	if in.EnableTUN && !in.AndroidMode {
		_ = tun.CleanupStaleRoutes(ctx, in.SudoPassword)
	}

	var xProc *managedProc
	if len(xraySpecs) > 0 {
		if xrayUseSudo {
			xProc, err = o.startProcessWithSudo("xray", xrayBin, []string{"run", "-config", xrayCfgPath}, in.SudoPassword)
		} else {
			xProc, err = o.startProcess("xray", xrayBin, []string{"run", "-config", xrayCfgPath})
		}
		if err != nil {
			msg := o.redactString(fmt.Sprintf("failed to start xray coprocessor: %v", err))
			o.setLastError(msg)
			return o.Status(), errors.New(msg)
		}
		if err := waitPortOrExit(ctx, xraySpecs[0].ListenPort, 3*time.Second, xProc.doneCh); err != nil {
			_ = terminateAndWait(xProc, 2*time.Second)
			msg := o.redactString(fmt.Sprintf("xray coprocessor failed to become ready: %v", err))
			o.AppendLog("xray", "error", msg)
			o.setLastError(msg)
			return o.Status(), errors.New(msg)
		}
		o.AppendLog("system", "info", fmt.Sprintf("xray v26 coprocessor started for %d node(s)", len(xraySpecs)))
	}

	var sbProc *managedProc
	var sbExtraEnv []string
	var coreCtrlAddr, coreCtrlToken, coreCtrlTokenFile, tsStatusToken string
	cacheDBPath := filepath.Join(o.workDir, "cache.db")
	if in.AndroidMode {
		if strings.TrimSpace(in.ProtectPath) != "" {
			sbExtraEnv = append(sbExtraEnv, "PRISMRAY_PROTECT_PATH="+strings.TrimSpace(in.ProtectPath))
		}
		if strings.TrimSpace(in.AndroidNetIfPath) != "" {
			sbExtraEnv = append(sbExtraEnv, "PRISMRAY_ANDROID_NETIF_PATH="+strings.TrimSpace(in.AndroidNetIfPath))
		}
	}
	useSudo := in.EnableTUN && !in.AndroidMode && (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !tun.CheckPrivilege(sbBin).ReadyWithoutPassword && len(in.SudoPassword) > 0
	if !useSudo {
		if f, oErr := os.OpenFile(cacheDBPath, os.O_RDWR, 0); oErr != nil {
			if os.IsPermission(oErr) {
				// Stale root-owned cache.db from an abruptly terminated sudo TUN session would wedge non-sudo startup.
				_ = os.Remove(cacheDBPath)
			}
		} else {
			_ = f.Close()
		}
	} else {
		sbExtraEnv = append(sbExtraEnv, "PRISMRAY_CACHE_DB_PATH="+cacheDBPath)
	}
	if in.Tailscale != nil && in.Tailscale.Enabled {
		tsStatusToken = randomHexSecret(16)
		sbExtraEnv = append(sbExtraEnv, "PRISMRAY_TAILSCALE_STATUS_TOKEN="+tsStatusToken)
		if strings.TrimSpace(in.TailscaleStatusPath) != "" {
			sbExtraEnv = append(sbExtraEnv, "PRISMRAY_TAILSCALE_STATUS_PATH="+strings.TrimSpace(in.TailscaleStatusPath))
		}
		if strings.TrimSpace(in.TailscaleStateDir) != "" {
			sbExtraEnv = append(sbExtraEnv, "PRISMRAY_TAILSCALE_STATE_DIR="+strings.TrimSpace(in.TailscaleStateDir))
		}
		if ctrlPort, portErr := freePort(); portErr == nil && ctrlPort > 0 {
			coreCtrlAddr = fmt.Sprintf("127.0.0.1:%d", ctrlPort)
			coreCtrlToken = randomHexSecret(32)
			o.registerLiteralSecret(coreCtrlToken)
			sbExtraEnv = append(sbExtraEnv, "PRISMRAY_CORE_CTRL_ADDR="+coreCtrlAddr)
			if useSudo {
				// Never pass the bearer secret in sudo argv (visible via ps / auth.log); write a 0600 temp file
				// that the unified sing-box wrapper reads and immediately unlinks on startup.
				tokPath := filepath.Join(o.workDir, ".core-ctrl-"+randomHexSecret(6))
				if wErr := fileutil.WritePrivate(tokPath, []byte(coreCtrlToken)); wErr == nil {
					coreCtrlTokenFile = tokPath
					sbExtraEnv = append(sbExtraEnv, "PRISMRAY_CORE_CTRL_TOKEN_FILE="+tokPath)
				}
			} else {
				sbExtraEnv = append(sbExtraEnv, "PRISMRAY_CORE_CTRL_TOKEN="+coreCtrlToken)
			}
		}
	}
	if useSudo {
		// Pass non-secret paths & addr via env wrapper when elevating with sudo.
		if len(sbExtraEnv) > 0 {
			sudoArgs := append([]string{}, sbExtraEnv...)
			sudoArgs = append(sudoArgs, sbBin, "run", "-c", sbCfgPath)
			sbProc, err = o.startProcessWithSudo("sing-box", "/usr/bin/env", sudoArgs, in.SudoPassword)
		} else {
			sbProc, err = o.startProcessWithSudo("sing-box", sbBin, []string{"run", "-c", sbCfgPath}, in.SudoPassword)
		}
	} else {
		sbProc, err = o.startProcessWithEnv("sing-box", sbBin, []string{"run", "-c", sbCfgPath}, sbExtraEnv)
	}
	if err != nil {
		if coreCtrlTokenFile != "" {
			_ = os.Remove(coreCtrlTokenFile)
		}
		_ = terminateAndWait(xProc, 2*time.Second)
		msg := o.redactString(fmt.Sprintf("failed to start sing-box: %v", err))
		o.setLastError(msg)
		return o.Status(), errors.New(msg)
	}

	clashClient := clashapi.New(fmt.Sprintf("127.0.0.1:%d", in.ClashAPIPort), in.ClashAPISecret)
	if err := waitClashReady(ctx, clashClient, o.readyTimeout, sbProc.doneCh); err != nil {
		if coreCtrlTokenFile != "" {
			_ = os.Remove(coreCtrlTokenFile)
		}
		_ = terminateAndWait(sbProc, 2*time.Second)
		_ = terminateAndWait(xProc, 2*time.Second)
		msg := o.redactString(fmt.Sprintf("sing-box failed to start: %v", err))
		o.AppendLog("sing-box", "error", msg)
		o.setLastError(msg)
		return o.Status(), errors.New(msg)
	}
	if coreCtrlTokenFile != "" {
		_ = os.Remove(coreCtrlTokenFile)
	}

	selMap := make(map[string]string, len(in.Groups))
	for _, g := range in.Groups {
		if target := desiredGroupTargetTag(g, compiled.IncludedTags); target != "" {
			selMap[g.ID] = target
		}
	}

	o.mu.Lock()
	o.singBoxProc = sbProc
	o.xrayProc = xProc
	o.running = true
	o.stopping = false
	o.startedAt = time.Now()
	o.topologyHash = topoHash
	o.includedTags = compiled.IncludedTags
	o.groupSelections = selMap
	o.lbShardTargets = compiled.LBShardTargets
	o.activeNodeID = in.ActiveNodeID
	o.activeGroupID = in.ActiveGroupID
	o.activeTag = compiled.ActiveTag
	o.tunEnabled = in.EnableTUN
	o.androidMode = in.AndroidMode
	o.mixedPort = in.MixedPort
	o.appSocksPort = appSocksPort
	o.appSocksSecret = appSocksSecret
	o.appPackages = append([]string(nil), appPackages...)
	o.clashAPIPort = in.ClashAPIPort
	o.clashAPISecret = in.ClashAPISecret
	o.clash = clashClient
	o.coreCtrlAddr = coreCtrlAddr
	o.coreCtrlToken = coreCtrlToken
	o.tailscaleStatusToken = tsStatusToken
	o.skippedNaive = compiled.SkippedNaive
	o.resolvedSB = sbBin
	o.resolvedXray = xrayBin
	o.lastError = ""
	o.mu.Unlock()

	o.watchExit(sbProc, "sing-box")
	if xProc != nil {
		o.watchExit(xProc, "xray")
	}

	o.AppendLog("system", "info", fmt.Sprintf("sing-box active (tag=%s, tun=%v, mixed=%d)", compiled.ActiveTag, in.EnableTUN, in.MixedPort))
	return o.Status(), nil
}

func desiredGroupTargetTag(g storage.Group, included map[string]bool) string {
	strat := storage.CanonicalGroupStrategy(g.Strategy)
	switch strat {
	case "selector":
		if g.SelectedNodeID == "" {
			return ""
		}
		if strings.TrimSpace(g.DetourID) != "" {
			if scoped := sbcfg.GroupScopedNodeTag(g.SelectedNodeID, g.ID); included[scoped] {
				return scoped
			}
		}
		if ntag := sbcfg.NodeTag(g.SelectedNodeID); included[ntag] {
			return ntag
		}
		return ""
	case "urltest", "failover":
		if g.ManualPin && g.SelectedNodeID != "" {
			if strings.TrimSpace(g.DetourID) != "" {
				if scoped := sbcfg.GroupScopedNodeTag(g.SelectedNodeID, g.ID); included[scoped] {
					return scoped
				}
			}
			if ntag := sbcfg.NodeTag(g.SelectedNodeID); included[ntag] {
				return ntag
			}
		}
		if autoTag := sbcfg.GroupAutoTag(g.ID); included[autoTag] {
			return autoTag
		}
		return ""
	default:
		return ""
	}
}

func (o *Orchestrator) tryHotSwitch(ctx context.Context, in ApplyInput, newTopoHash string) bool {
	o.mu.RLock()
	running := o.running
	prevHash := o.topologyHash
	included := o.includedTags
	clash := o.clash
	sbProc := o.singBoxProc
	xProc := o.xrayProc
	prevSelections := make(map[string]string, len(o.groupSelections))
	for k, v := range o.groupSelections {
		prevSelections[k] = v
	}
	o.mu.RUnlock()

	if !running || clash == nil || sbProc == nil || prevHash != newTopoHash {
		return false
	}
	if !processAlive(sbProc) || (xProc != nil && !processAlive(xProc)) {
		return false
	}

	var targetTag string
	if in.ActiveGroupID != "" && included[sbcfg.GroupTag(in.ActiveGroupID)] {
		targetTag = sbcfg.GroupTag(in.ActiveGroupID)
	} else if in.ActiveNodeID != "" && included[sbcfg.NodeTag(in.ActiveNodeID)] {
		targetTag = sbcfg.NodeTag(in.ActiveNodeID)
	} else {
		return false
	}

	nextSelections := make(map[string]string, len(in.Groups))
	for _, g := range in.Groups {
		desired := desiredGroupTargetTag(g, included)
		if desired == "" {
			continue
		}
		nextSelections[g.ID] = desired
		if desired == prevSelections[g.ID] {
			continue
		}
		gtag := sbcfg.GroupTag(g.ID)
		if !included[gtag] || !included[desired] {
			continue
		}
		if err := clash.SelectProxy(ctx, gtag, desired); err != nil {
			return false
		}
	}

	if err := clash.SelectProxy(ctx, "proxy", targetTag); err != nil {
		return false
	}

	o.mu.Lock()
	o.activeNodeID = in.ActiveNodeID
	o.activeGroupID = in.ActiveGroupID
	o.activeTag = targetTag
	o.groupSelections = nextSelections
	o.lastError = ""
	o.mu.Unlock()

	o.AppendLog("system", "info", fmt.Sprintf("hot-switched active outbound to %s via Clash API without restarting TUN", targetTag))
	return true
}

// HotSwitch switches a selector group member on the live sing-box instance without restarting.
func (o *Orchestrator) HotSwitch(ctx context.Context, selectorTag, targetTag string) error {
	o.opMu.Lock()
	defer o.opMu.Unlock()

	o.mu.RLock()
	running := o.running
	clash := o.clash
	included := o.includedTags
	o.mu.RUnlock()

	if !running || clash == nil {
		return fmt.Errorf("proxy core is not running")
	}
	if !included[selectorTag] || !included[targetTag] {
		return fmt.Errorf("selector %q or target %q not loaded in active topology", selectorTag, targetTag)
	}
	if err := clash.SelectProxy(ctx, selectorTag, targetTag); err != nil {
		return err
	}

	o.mu.Lock()
	if selectorTag == "proxy" {
		o.activeTag = targetTag
		if strings.HasPrefix(targetTag, "node-") {
			o.activeNodeID = strings.TrimPrefix(targetTag, "node-")
			o.activeGroupID = ""
		} else if strings.HasPrefix(targetTag, "group-") {
			o.activeGroupID = strings.TrimPrefix(targetTag, "group-")
		}
	} else if strings.HasPrefix(selectorTag, "group-") && !strings.HasSuffix(selectorTag, "-auto") {
		gid := strings.TrimPrefix(selectorTag, "group-")
		o.groupSelections[gid] = targetTag
	}
	o.mu.Unlock()
	return nil
}

// SetLBShardsBlocked switches every shard selector wrapper of the specified load-balance group
// to block-out (when blocked=true) or back to its primary healthy shard member (when blocked=false).
func (o *Orchestrator) SetLBShardsBlocked(ctx context.Context, groupID string, blocked bool) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return
	}
	o.mu.RLock()
	running := o.running
	clash := o.clash
	included := o.includedTags
	targets := append([]string(nil), o.lbShardTargets[groupID]...)
	o.mu.RUnlock()
	if !running || clash == nil || len(targets) == 0 {
		return
	}
	for i, memberTag := range targets {
		selTag := sbcfg.LBShardSelectorTag(groupID, i)
		if !included[selTag] {
			continue
		}
		desired := memberTag
		if blocked {
			desired = sbcfg.BlockOutboundTag
		}
		if !included[desired] {
			continue
		}
		_ = clash.SelectProxy(ctx, selTag, desired)
	}
}

// RestoreAllLBShards unblocks every load-balance shard selector back to its default healthy member.
func (o *Orchestrator) RestoreAllLBShards(ctx context.Context) {
	o.mu.RLock()
	running := o.running
	clash := o.clash
	included := o.includedTags
	snapshot := make(map[string][]string, len(o.lbShardTargets))
	for gid, targets := range o.lbShardTargets {
		snapshot[gid] = append([]string(nil), targets...)
	}
	o.mu.RUnlock()
	if !running || clash == nil || len(snapshot) == 0 {
		return
	}
	for gid, targets := range snapshot {
		for i, memberTag := range targets {
			selTag := sbcfg.LBShardSelectorTag(gid, i)
			if included[selTag] && included[memberTag] {
				_ = clash.SelectProxy(ctx, selTag, memberTag)
			}
		}
	}
}

// Stop terminates both sing-box and any active Xray coprocessor cleanly.
func (o *Orchestrator) Stop() error {
	o.opMu.Lock()
	defer o.opMu.Unlock()
	o.stopLocked()
	return nil
}

// Close implements io.Closer.
func (o *Orchestrator) Close() error {
	return o.Stop()
}

func (o *Orchestrator) stopLocked() {
	o.resetTailscaleTelemetry("")
	o.mu.Lock()
	sbProc := o.singBoxProc
	xProc := o.xrayProc
	wasRunning := o.running
	o.stopping = true
	o.running = false
	o.singBoxProc = nil
	o.xrayProc = nil
	o.clash = nil
	o.topologyHash = ""
	o.includedTags = map[string]bool{}
	o.lbShardTargets = nil
	o.tunEnabled = false
	o.activeTag = ""
	o.appSocksPort = 0
	o.appSocksSecret = ""
	o.appPackages = nil
	o.mu.Unlock()

	_ = terminateAndWait(sbProc, 2*time.Second)
	_ = terminateAndWait(xProc, 2*time.Second)
	if wasRunning {
		o.AppendLog("system", "info", "proxy cores stopped")
	}
}

// Status returns a point-in-time snapshot of the running cores.
func (o *Orchestrator) Status() Status {
	o.mu.RLock()
	defer o.mu.RUnlock()

	sbUp := processAlive(o.singBoxProc)
	xUp := processAlive(o.xrayProc)
	st := Status{
		Running:         o.running && sbUp,
		SingBoxRunning:  sbUp,
		XrayRunning:     xUp,
		ActiveNodeID:    o.activeNodeID,
		ActiveGroupID:   o.activeGroupID,
		ActiveTag:       o.activeTag,
		TUNEnabled:      o.tunEnabled && sbUp,
		AndroidMode:     o.androidMode,
		MixedPort:       o.mixedPort,
		AppSocksPort:    o.appSocksPort,
		AppSocksSecret:  o.appSocksSecret,
		ClashAPIPort:    o.clashAPIPort,
		LastError:       o.lastError,
		ResolvedSingBox: o.resolvedSB,
		ResolvedXray:    o.resolvedXray,
	}
	if len(o.appPackages) > 0 {
		st.AppPackages = append([]string(nil), o.appPackages...)
	}
	if len(o.skippedNaive) > 0 {
		st.SkippedNaive = append([]string(nil), o.skippedNaive...)
	}
	if o.singBoxProc != nil {
		st.SingBoxPID = o.singBoxProc.pid
	}
	if o.xrayProc != nil {
		st.XrayPID = o.xrayProc.pid
	}
	if st.Running && !o.startedAt.IsZero() {
		st.UptimeSeconds = int64(time.Since(o.startedAt).Seconds())
	}
	return st
}

// ClashClient returns the Clash API client bound to the live sing-box instance, or nil if stopped.
func (o *Orchestrator) ClashClient() *clashapi.Client {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if !o.running {
		return nil
	}
	return o.clash
}

// ResolveLiveGroupSelection queries the live Clash API to resolve a selector/urltest/loadbalance
// group tag to its currently active leaf outbound tag (e.g. "node-<id>").
func (o *Orchestrator) ResolveLiveGroupSelection(ctx context.Context, groupTag string) string {
	client := o.ClashClient()
	if client == nil || strings.TrimSpace(groupTag) == "" {
		return ""
	}
	qctx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	res, err := client.GetProxies(qctx)
	if err != nil || res == nil || len(res.Proxies) == 0 {
		return ""
	}
	curr := strings.TrimSpace(groupTag)
	seen := map[string]bool{}
	for depth := 0; depth < 6; depth++ {
		if seen[curr] {
			break
		}
		seen[curr] = true
		info, ok := res.Proxies[curr]
		if !ok || strings.TrimSpace(info.Now) == "" {
			break
		}
		curr = strings.TrimSpace(info.Now)
	}
	if curr == strings.TrimSpace(groupTag) {
		return ""
	}
	return curr
}

// ResolveAllGroupSelections queries Clash API once and resolves every top-level policy group
// ("group-<id>") to its currently active leaf node ID (stripping "node-" prefix and "--via-..." suffix).
func (o *Orchestrator) ResolveAllGroupSelections(ctx context.Context) map[string]string {
	client := o.ClashClient()
	if client == nil {
		return nil
	}
	qctx, cancel := context.WithTimeout(ctx, 450*time.Millisecond)
	defer cancel()
	res, err := client.GetProxies(qctx)
	if err != nil || res == nil || len(res.Proxies) == 0 {
		return nil
	}
	out := map[string]string{}
	for tag := range res.Proxies {
		if !strings.HasPrefix(tag, "group-") || strings.HasSuffix(tag, "-auto") || strings.Contains(tag, "--via-") {
			continue
		}
		curr := tag
		seen := map[string]bool{}
		for depth := 0; depth < 6; depth++ {
			if seen[curr] {
				break
			}
			seen[curr] = true
			info, ok := res.Proxies[curr]
			if !ok || strings.TrimSpace(info.Now) == "" {
				break
			}
			curr = strings.TrimSpace(info.Now)
		}
		if strings.HasPrefix(curr, "node-") {
			nid := strings.TrimPrefix(curr, "node-")
			if idx := strings.Index(nid, "--via-"); idx > 0 {
				nid = nid[:idx]
			}
			if nid != "" {
				out[strings.TrimPrefix(tag, "group-")] = nid
			}
		}
	}
	return out
}

func collectAndroidRulePackages(routing ruleset.RoutingProfile) []string {
	if !routing.CustomRulesEnabledOrDefault() {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, cr := range routing.CustomRules {
		if !cr.Enabled {
			continue
		}
		for _, pkg := range cr.PackageName {
			clean := strings.TrimSpace(pkg)
			if clean == "" || seen[clean] {
				continue
			}
			seen[clean] = true
			out = append(out, clean)
		}
	}
	sort.Strings(out)
	return out
}

// LogHistory returns up to limit most recent redacted log entries (all if limit <= 0).
func (o *Orchestrator) LogHistory(limit int) []LogEntry {
	o.logMu.Lock()
	defer o.logMu.Unlock()

	n := o.logCount
	if n == 0 {
		return nil
	}
	if limit > 0 && limit < n {
		n = limit
	}
	capLen := len(o.logs)
	start := (o.logHead - n + capLen) % capLen
	out := make([]LogEntry, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, o.logs[(start+i)%capLen])
	}
	return out
}

// SubscribeLogs registers a live log stream listener and returns a channel alongside its unsubscribe callback.
func (o *Orchestrator) SubscribeLogs() (<-chan LogEntry, func()) {
	ch := make(chan LogEntry, 128)
	id := o.subSeq.Add(1)

	o.logMu.Lock()
	o.subscribers[id] = ch
	o.logMu.Unlock()

	cancel := func() {
		o.logMu.Lock()
		if existing, ok := o.subscribers[id]; ok {
			delete(o.subscribers, id)
			close(existing)
		}
		o.logMu.Unlock()
	}
	return ch, cancel
}

var (
	// Matches full ANSI CSI/OSC escape sequences (ESC[...m etc.).
	ansiEscapeRE = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))`)
	// Matches orphaned SGR color sequences when ESC byte was stripped (e.g. "[36m", "[38;5;184m", "[0m").
	bareSGRRE = regexp.MustCompile(`\[(?:\d{1,3}(?:;\d{1,3})*)m`)
	// Matches sing-box outbound node tags in log lines (e.g. outbound/vless[node-xxx]: ...).
	outboundNodeLogRE = regexp.MustCompile(`outbound/[a-zA-Z0-9_-]+\[(node-[^\]]+)\]`)
	// Matches Tailscale interactive login URLs logged by sing-box endpoint/tailscale.
	tailscaleAuthURLRE = regexp.MustCompile(`Waiting for authentication:\s*(https?://\S+)`)
)

func isOutboundFailureLine(level, msg string) bool {
	low := strings.ToLower(msg)
	if strings.Contains(low, "i/o timeout") ||
		strings.Contains(low, "context deadline exceeded") ||
		strings.Contains(low, "connection refused") ||
		strings.Contains(low, "connection reset by peer") ||
		strings.Contains(low, "unexpected eof") ||
		strings.Contains(low, "network is unreachable") ||
		strings.Contains(low, "no route to host") ||
		strings.Contains(low, "handshake failure") ||
		strings.Contains(low, "broken pipe") ||
		strings.Contains(low, "closed network connection") {
		return true
	}
	return level == "error" && (strings.Contains(low, "dial ") || strings.Contains(low, "eof") || strings.Contains(low, "timeout"))
}

var singBoxTimestampPrefixRE = regexp.MustCompile(`^(?:[+-]\d{4}\s+)?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+`)

// StripANSI removes ANSI terminal escape codes and orphaned SGR color fragments from log lines.
func StripANSI(s string) string {
	s = ansiEscapeRE.ReplaceAllString(s, "")
	s = bareSGRRE.ReplaceAllString(s, "")
	return s
}

// AppendLog records a structured log entry after stripping ANSI control codes and applying secret redaction.
func (o *Orchestrator) AppendLog(core, level, msg string) {
	msg = strings.TrimSpace(StripANSI(msg))
	if msg == "" {
		return
	}
	// Standalone sing-box CLI on non-root Android always logs a harmless package manager
	// permission warning on startup because Per-App Proxy is handled by Android VpnService.
	if core == "sing-box" &&
		strings.Contains(msg, "initialize package manager") &&
		strings.Contains(msg, "/data/system/packages.xml") {
		return
	}
	msg = o.redactString(msg)
	if level == "" {
		level = inferLogLevel(msg)
	}
	// Remove redundant leading sing-box timestamp + level prefix (e.g. "+0000 2026-11-26 18:06:01 ERROR ")
	// because PrismRay already tags every log entry with local-timezone Timestamp and structured Level.
	if core == "sing-box" {
		if trimmed := strings.TrimSpace(singBoxTimestampPrefixRE.ReplaceAllString(msg, "")); trimmed != "" {
			msg = trimmed
		}
	}
	entry := LogEntry{
		Seq:       o.logSeq.Add(1),
		Timestamp: time.Now().Format(time.RFC3339),
		Core:      core,
		Level:     strings.ToLower(level),
		Message:   msg,
	}

	o.logMu.Lock()
	capLen := len(o.logs)
	o.logs[o.logHead] = entry
	o.logHead = (o.logHead + 1) % capLen
	if o.logCount < capLen {
		o.logCount++
	}
	for _, sub := range o.subscribers {
		select {
		case sub <- entry:
		default:
		}
	}
	o.logMu.Unlock()

	if core == "sing-box" {
		o.inspectTailscaleLog(entry.Level, msg)
	}
	if core == "sing-box" && isOutboundFailureLine(entry.Level, msg) {
		if m := outboundNodeLogRE.FindStringSubmatch(msg); len(m) == 2 {
			tag := m[1]
			now := time.Now()
			o.failThrottleMu.Lock()
			if o.lastFailEmit == nil {
				o.lastFailEmit = make(map[string]time.Time)
			}
			allowEmit := now.Sub(o.lastFailEmit[tag]) >= 500*time.Millisecond
			if allowEmit {
				o.lastFailEmit[tag] = now
			}
			o.failThrottleMu.Unlock()
			if allowEmit {
				o.failHandlerMu.RLock()
				fn := o.onOutboundFailure
				o.failHandlerMu.RUnlock()
				if fn != nil {
					go fn(tag, msg)
				}
			}
		}
	}
}

func (o *Orchestrator) inspectTailscaleLog(level, msg string) {
	low := strings.ToLower(msg)
	if !strings.Contains(low, "tailscale") && !strings.Contains(low, "tsnet") {
		return
	}
	if m := tailscaleAuthURLRE.FindStringSubmatch(msg); len(m) == 2 {
		o.tsStatusMu.Lock()
		o.tsAuthURL = strings.TrimSpace(m[1])
		o.tsUpdatedAt = time.Now().UTC()
		o.tsStatusMu.Unlock()
		return
	}
	if level == "error" || level == "fatal" || strings.Contains(low, "fatal[") || strings.Contains(low, "post-start endpoint/tailscale") {
		o.tsStatusMu.Lock()
		o.tsLastError = msg
		o.tsUpdatedAt = time.Now().UTC()
		o.tsStatusMu.Unlock()
	}
}

// ProbeNodes concurrently measures true proxy round-trip latencies across candidate nodes.
func (o *Orchestrator) ProbeNodes(ctx context.Context, nodes []*config.Node, testURL string, timeout time.Duration) map[string]ProbeResult {
	return o.ProbeNodesWithOptions(ctx, nodes, ProbeOptions{
		Mode:    "urltest",
		TestURL: testURL,
		Timeout: timeout,
	})
}

func normalizeProbeMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ping", "tcp":
		return "ping"
	case "speed", "bandwidth":
		return "speed"
	case "full", "all":
		return "full"
	default:
		return "urltest"
	}
}

func dialTCPPing(ctx context.Context, n *config.Node, timeout time.Duration) (int64, error) {
	if n == nil || strings.TrimSpace(n.Address) == "" || n.Port < 1 {
		return -1, fmt.Errorf("invalid node address")
	}
	target := net.JoinHostPort(strings.TrimSpace(n.Address), strconv.Itoa(n.Port))
	dialer := &net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target)
	elapsed := time.Since(start)
	if err != nil {
		return -1, err
	}
	_ = conn.Close()
	ms := elapsed.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

func roundMbps(bytes int64, d time.Duration) float64 {
	sec := d.Seconds()
	if sec <= 0 || bytes <= 0 {
		return 0
	}
	mbps := float64(bytes) * 8 / sec / 1e6
	return math.Round(mbps*100) / 100
}

// ProbeNodesWithOptions executes TCP ping, URL delay, and/or real up/down bandwidth probes.
func (o *Orchestrator) ProbeNodesWithOptions(ctx context.Context, nodes []*config.Node, opts ProbeOptions) map[string]ProbeResult {
	mode := normalizeProbeMode(opts.Mode)
	testURL := strings.TrimSpace(opts.TestURL)
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	speedDownURL := strings.TrimSpace(opts.SpeedDownURL)
	if speedDownURL == "" {
		speedDownURL = defaultSpeedDownURL
	}
	speedUpURL := strings.TrimSpace(opts.SpeedUpURL)
	if speedUpURL == "" {
		speedUpURL = defaultSpeedUpURL
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	timeoutMS := int(timeout.Milliseconds())
	if timeoutMS <= 0 {
		timeoutMS = 5000
	}

	results := make(map[string]ProbeResult, len(nodes))
	seen := make(map[string]bool, len(nodes))
	var validNodes []*config.Node
	for _, n := range nodes {
		if n == nil || n.ID == "" || seen[n.ID] {
			continue
		}
		seen[n.ID] = true
		if err := n.Validate(); err != nil {
			results[n.ID] = ProbeResult{NodeID: n.ID, LatencyMS: -1, PingMS: -1, Mode: mode, Error: err.Error()}
			continue
		}
		validNodes = append(validNodes, n)
	}
	if len(validNodes) == 0 {
		return results
	}

	// Fast TCP handshake RTT mode (and Ping phase for full mode).
	pingMap := make(map[string]int64, len(validNodes))
	if mode == "ping" || mode == "full" {
		var pingMu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, probeConcurrency)
		for _, n := range validNodes {
			n := n
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				ms, err := dialTCPPing(ctx, n, timeout)
				pingMu.Lock()
				pingMap[n.ID] = ms
				if mode == "ping" {
					r := ProbeResult{NodeID: n.ID, PingMS: ms, Mode: mode}
					if err != nil {
						r.LatencyMS = -1
						r.Error = o.redactString(err.Error())
					} else {
						r.LatencyMS = ms
					}
					results[n.ID] = r
				}
				pingMu.Unlock()
			}()
		}
		wg.Wait()
		if mode == "ping" {
			return results
		}
	}

	urlsToCheck := []string{testURL}
	if speedDownURL != "" {
		urlsToCheck = append(urlsToCheck, speedDownURL)
	}
	if speedUpURL != "" {
		urlsToCheck = append(urlsToCheck, speedUpURL)
	}
	for _, uRaw := range urlsToCheck {
		parsedURL, parseErr := url.Parse(uRaw)
		if parseErr != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" {
			for _, n := range validNodes {
				results[n.ID] = ProbeResult{NodeID: n.ID, LatencyMS: -1, Mode: mode, Error: "probe URL must use HTTPS"}
			}
			return results
		}
	}

	sbBin, sbErr := o.ResolveSingBoxBinary()
	if sbErr != nil {
		for _, n := range validNodes {
			results[n.ID] = ProbeResult{NodeID: n.ID, LatencyMS: -1, PingMS: pingMap[n.ID], Mode: mode, Error: sbErr.Error()}
		}
		return results
	}
	includeNaive := sbcfg.CronetAvailable(sbBin)

	var filteredNodes []*config.Node
	for _, n := range validNodes {
		if n.Protocol == config.ProtocolNaive && !includeNaive {
			results[n.ID] = ProbeResult{NodeID: n.ID, LatencyMS: -1, PingMS: pingMap[n.ID], Mode: mode, Error: "libcronet is unavailable for NaiveProxy node"}
			continue
		}
		filteredNodes = append(filteredNodes, n)
	}
	if len(filteredNodes) == 0 {
		return results
	}

	localDNS := strings.TrimSpace(opts.LocalDNS)
	if localDNS == "" {
		localDNS = "223.5.5.5"
	}

	if mode == "speed" || mode == "full" {
		for start := 0; start < len(filteredNodes); start += speedBatchSize {
			end := start + speedBatchSize
			if end > len(filteredNodes) {
				end = len(filteredNodes)
			}
			batch := o.probeSpeedBatch(ctx, sbBin, includeNaive, filteredNodes[start:end], opts.AllNodes, opts.AllGroups, mode, testURL, speedDownURL, speedUpURL, localDNS, opts.AndroidMode, opts.ProtectPath, timeout)
			for _, r := range batch {
				if p, ok := pingMap[r.NodeID]; ok {
					r.PingMS = p
				}
				results[r.NodeID] = r
			}
		}
		return results
	}

	// Default urltest mode: live Clash API fast path + single sandbox batch.
	var liveNodes []*config.Node
	var sandboxNodes []*config.Node
	liveClient := o.ClashClient()
	if liveClient != nil {
		pCtx, pCancel := context.WithTimeout(ctx, 2*time.Second)
		proxiesRes, err := liveClient.GetProxies(pCtx)
		pCancel()
		if err == nil {
			for _, n := range filteredNodes {
				if _, ok := proxiesRes.Proxies[sbcfg.NodeTag(n.ID)]; ok {
					liveNodes = append(liveNodes, n)
					continue
				}
				sandboxNodes = append(sandboxNodes, n)
			}
		} else {
			sandboxNodes = filteredNodes
		}
	} else {
		sandboxNodes = filteredNodes
	}

	var resMu sync.Mutex
	record := func(r ProbeResult) {
		r.Mode = mode
		resMu.Lock()
		results[r.NodeID] = r
		resMu.Unlock()
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, probeConcurrency)

	for _, n := range liveNodes {
		n := n
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			delay, err := liveClient.ProbeDelay(ctx, sbcfg.NodeTag(n.ID), testURL, timeoutMS)
			if err != nil {
				record(ProbeResult{NodeID: n.ID, LatencyMS: -1, Error: o.redactString(err.Error())})
				return
			}
			record(ProbeResult{NodeID: n.ID, LatencyMS: int64(delay)})
		}()
	}

	if len(sandboxNodes) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			batch := o.probeInSingleSandbox(ctx, sbBin, includeNaive, sandboxNodes, opts.AllNodes, opts.AllGroups, testURL, localDNS, opts.AndroidMode, opts.ProtectPath, timeoutMS)
			for _, r := range batch {
				record(r)
			}
		}()
	}

	wg.Wait()
	return results
}

func (o *Orchestrator) makeTempDir(prefix string) (string, error) {
	if strings.TrimSpace(o.workDir) != "" {
		base := filepath.Join(o.workDir, "tmp")
		if err := os.MkdirAll(base, 0o700); err == nil {
			return os.MkdirTemp(base, prefix)
		}
	}
	return os.MkdirTemp("", prefix)
}

func (o *Orchestrator) probeSpeedBatch(
	ctx context.Context,
	sbBin string,
	includeNaive bool,
	nodes []*config.Node,
	allNodes []*config.Node,
	allGroups []storage.Group,
	mode string,
	testURL string,
	downURL string,
	upURL string,
	localDNS string,
	androidMode bool,
	protectPath string,
	timeout time.Duration,
) []ProbeResult {
	failAll := func(errMsg string) []ProbeResult {
		out := make([]ProbeResult, 0, len(nodes))
		for _, n := range nodes {
			out = append(out, ProbeResult{NodeID: n.ID, LatencyMS: -1, Mode: mode, Error: errMsg})
		}
		return out
	}

	tmpDir, err := o.makeTempDir("prismray-speed-*")
	if err != nil {
		return failAll(err.Error())
	}
	defer os.RemoveAll(tmpDir)

	compileNodes, compileGroups := expandDetourDependencies(nodes, allNodes, allGroups)

	var xraySpecs []xraycfg.BridgeSpec
	bridgePorts := map[string]int{}
	for _, n := range compileNodes {
		if n.RequiresXray() {
			p, err := freePort()
			if err != nil {
				return failAll(err.Error())
			}
			bridgePorts[n.ID] = p
			xraySpecs = append(xraySpecs, xraycfg.BridgeSpec{Node: n, ListenPort: p})
		}
	}

	if len(xraySpecs) > 0 {
		xrayBin, err := o.ResolveXrayBinary()
		if err != nil {
			return failAll(fmt.Sprintf("Xray binary missing for speed test: %v", err))
		}
		xDoc, err := xraycfg.GenerateProbeConfig(xraySpecs)
		if err != nil {
			return failAll(err.Error())
		}
		xJSON, err := xDoc.ToJSON()
		if err != nil {
			return failAll(err.Error())
		}
		xCfgPath := filepath.Join(tmpDir, "xray-speed.json")
		if err := os.WriteFile(xCfgPath, xJSON, 0o600); err != nil {
			return failAll(err.Error())
		}
		xProc, err := spawnRaw("xray-speed", xrayBin, []string{"run", "-config", xCfgPath}, nil)
		if err != nil {
			return failAll(err.Error())
		}
		defer terminateAndWait(xProc, 2*time.Second)
		if err := waitPortOrExit(ctx, xraySpecs[0].ListenPort, 3*time.Second, xProc.doneCh); err != nil {
			return failAll(fmt.Sprintf("speed xray failed: %v", err))
		}
	}

	clashPort, err := freePort()
	if err != nil {
		return failAll(err.Error())
	}
	mixedPort, err := freePort()
	if err != nil {
		return failAll(err.Error())
	}

	nodePorts := make(map[string]int, len(nodes))
	listeners := make([]*config.ListenConfig, 0, len(nodes))
	for i, n := range nodes {
		lp, err := freePort()
		if err != nil {
			return failAll(err.Error())
		}
		nodePorts[n.ID] = lp
		listeners = append(listeners, &config.ListenConfig{
			ID:       fmt.Sprintf("spd-%d", i),
			Name:     "speed-" + n.ID,
			Protocol: "mixed",
			Address:  "127.0.0.1",
			Port:     lp,
			NodeIDs:  []string{n.ID},
			Enabled:  true,
		})
	}

	clashSecret := randomHexSecret(12)
	compiled, err := sbcfg.Compile(sbcfg.CompileInput{
		Nodes:          compileNodes,
		Groups:         compileGroups,
		Listeners:      listeners,
		ActiveNodeID:   nodes[0].ID,
		MixedPort:      mixedPort,
		ClashAPIPort:   clashPort,
		ClashAPISecret: clashSecret,
		EnableTUN:      false,
		AndroidMode:    androidMode,
		ProtectPath:    protectPath,
		Routing: ruleset.RoutingProfile{
			Mode:           "rule",
			DomainStrategy: "prefer_ipv4",
			LocalDNS:       localDNS,
			RemoteDNS:      "https://1.1.1.1/dns-query",
			WebRTCMode:     "direct",
			LogLevel:       "error",
		},
		XrayBridgePorts: bridgePorts,
		IncludeNaive:    includeNaive,
	})
	if err != nil {
		return failAll(err.Error())
	}

	sbCfgPath := filepath.Join(tmpDir, "sing-box-speed.json")
	if err := os.WriteFile(sbCfgPath, compiled.Raw, 0o600); err != nil {
		return failAll(err.Error())
	}
	var speedStderr stderrTail
	sbProc, err := spawnRaw("sing-box-speed", sbBin, []string{"run", "-c", sbCfgPath}, speedStderr.Add)
	if err != nil {
		return failAll(err.Error())
	}
	defer terminateAndWait(sbProc, 2*time.Second)

	sandboxClash := clashapi.New(fmt.Sprintf("127.0.0.1:%d", clashPort), clashSecret)
	if err := waitClashReady(ctx, sandboxClash, 5*time.Second, sbProc.doneCh); err != nil {
		if detail := speedStderr.Summary(o.redactString); detail != "" {
			return failAll(fmt.Sprintf("speed sandbox failed: %v (%s)", err, detail))
		}
		return failAll(fmt.Sprintf("speed sandbox failed: %v", err))
	}

	results := make([]ProbeResult, len(nodes))
	var wg sync.WaitGroup
	sem := make(chan struct{}, speedConcurrency)
	for i, n := range nodes {
		i, n := i, n
		port := nodePorts[n.ID]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			transport := &http.Transport{
				Proxy:                 http.ProxyURL(proxyURL),
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}

			res := ProbeResult{NodeID: n.ID, Mode: mode}

			// Optional real-connection latency test in full mode (or fallback check).
			if mode == "full" {
				latCtx, latCancel := context.WithTimeout(ctx, timeout)
				req, reqErr := http.NewRequestWithContext(latCtx, http.MethodGet, testURL, nil)
				if reqErr == nil {
					t0 := time.Now()
					resp, doErr := client.Do(req)
					elapsed := time.Since(t0)
					if doErr == nil {
						_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
						_ = resp.Body.Close()
						ms := elapsed.Milliseconds()
						if ms < 1 {
							ms = 1
						}
						res.LatencyMS = ms
					} else {
						res.LatencyMS = -1
						res.Error = o.redactString(doErr.Error())
					}
				}
				latCancel()
			}

			// Measure download throughput (up to 4s active transfer window).
			dlCtx, dlCancel := context.WithTimeout(ctx, max(timeout, 6*time.Second))
			dlReq, dlReqErr := http.NewRequestWithContext(dlCtx, http.MethodGet, downURL, nil)
			if dlReqErr == nil {
				dlReq.Header.Set("User-Agent", "PrismRay/1.1.0")
				resp, dlErr := client.Do(dlReq)
				if dlErr == nil {
					readStart := time.Now()
					readDeadline := time.NewTimer(4 * time.Second)
					go func() {
						select {
						case <-readDeadline.C:
							dlCancel()
						case <-dlCtx.Done():
						}
					}()
					nBytes, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 25<<20))
					readElapsed := time.Since(readStart)
					readDeadline.Stop()
					_ = resp.Body.Close()
					if nBytes > 0 && readElapsed > 20*time.Millisecond {
						res.DownSpeedMbps = roundMbps(nBytes, readElapsed)
					}
				} else if res.Error == "" {
					res.LatencyMS = -1
					res.Error = o.redactString(dlErr.Error())
				}
			}
			dlCancel()

			// Measure upload throughput (up to 4s active transfer / 2 MiB payload).
			ulCtx, ulCancel := context.WithTimeout(ctx, max(timeout, 6*time.Second))
			const upLimit = 2 << 20
			pr, pw := io.Pipe()
			var sentBytes int64
			go func() {
				buf := make([]byte, 32*1024)
				var total int64
				for total < upLimit {
					chunk := len(buf)
					if rem := int(upLimit - total); rem < chunk {
						chunk = rem
					}
					w, wErr := pw.Write(buf[:chunk])
					total += int64(w)
					if wErr != nil {
						break
					}
				}
				_ = pw.Close()
			}()
			ulReq, ulReqErr := http.NewRequestWithContext(ulCtx, http.MethodPost, upURL, pr)
			if ulReqErr == nil {
				ulReq.ContentLength = upLimit
				ulReq.Header.Set("Content-Type", "application/octet-stream")
				ulReq.Header.Set("User-Agent", "PrismRay/1.1.0")
				ulStart := time.Now()
				resp, ulErr := client.Do(ulReq)
				ulElapsed := time.Since(ulStart)
				if ulErr == nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
					_ = resp.Body.Close()
					sentBytes = upLimit
					res.UpSpeedMbps = roundMbps(sentBytes, ulElapsed)
				}
			}
			_ = pr.Close()
			ulCancel()

			results[i] = res
		}()
	}
	wg.Wait()
	return results
}

func (o *Orchestrator) probeInSingleSandbox(
	ctx context.Context,
	sbBin string,
	includeNaive bool,
	nodes []*config.Node,
	allNodes []*config.Node,
	allGroups []storage.Group,
	testURL string,
	localDNS string,
	androidMode bool,
	protectPath string,
	timeoutMS int,
) []ProbeResult {
	failAll := func(errMsg string) []ProbeResult {
		out := make([]ProbeResult, 0, len(nodes))
		for _, n := range nodes {
			out = append(out, ProbeResult{NodeID: n.ID, LatencyMS: -1, Error: errMsg})
		}
		return out
	}

	tmpDir, err := o.makeTempDir("prismray-probe-*")
	if err != nil {
		return failAll(err.Error())
	}
	defer os.RemoveAll(tmpDir)

	compileNodes, compileGroups := expandDetourDependencies(nodes, allNodes, allGroups)

	var xraySpecs []xraycfg.BridgeSpec
	bridgePorts := map[string]int{}
	for _, n := range compileNodes {
		if n.RequiresXray() {
			p, err := freePort()
			if err != nil {
				return failAll(err.Error())
			}
			bridgePorts[n.ID] = p
			xraySpecs = append(xraySpecs, xraycfg.BridgeSpec{Node: n, ListenPort: p})
		}
	}

	var xProc *managedProc
	if len(xraySpecs) > 0 {
		xrayBin, err := o.ResolveXrayBinary()
		if err != nil {
			return failAll(fmt.Sprintf("Xray binary missing for probe: %v", err))
		}
		xDoc, err := xraycfg.GenerateProbeConfig(xraySpecs)
		if err != nil {
			return failAll(err.Error())
		}
		xJSON, err := xDoc.ToJSON()
		if err != nil {
			return failAll(err.Error())
		}
		xCfgPath := filepath.Join(tmpDir, "xray-probe.json")
		if err := os.WriteFile(xCfgPath, xJSON, 0o600); err != nil {
			return failAll(err.Error())
		}
		xProc, err = spawnRaw("xray-probe", xrayBin, []string{"run", "-config", xCfgPath}, nil)
		if err != nil {
			return failAll(err.Error())
		}
		defer terminateAndWait(xProc, 2*time.Second)
		if err := waitPortOrExit(ctx, xraySpecs[0].ListenPort, 3*time.Second, xProc.doneCh); err != nil {
			return failAll(fmt.Sprintf("probe xray failed: %v", err))
		}
	}

	clashPort, err := freePort()
	if err != nil {
		return failAll(err.Error())
	}
	mixedPort, err := freePort()
	if err != nil {
		return failAll(err.Error())
	}
	clashSecret := randomHexSecret(12)

	compiled, err := sbcfg.Compile(sbcfg.CompileInput{
		Nodes:          compileNodes,
		Groups:         compileGroups,
		ActiveNodeID:   nodes[0].ID,
		MixedPort:      mixedPort,
		ClashAPIPort:   clashPort,
		ClashAPISecret: clashSecret,
		EnableTUN:      false,
		AndroidMode:    androidMode,
		ProtectPath:    protectPath,
		Routing: ruleset.RoutingProfile{
			Mode:           "rule",
			DomainStrategy: "prefer_ipv4",
			LocalDNS:       localDNS,
			RemoteDNS:      "https://1.1.1.1/dns-query",
			LogLevel:       "error",
		},
		XrayBridgePorts: bridgePorts,
		IncludeNaive:    includeNaive,
	})
	if err != nil {
		return failAll(err.Error())
	}

	sbCfgPath := filepath.Join(tmpDir, "sing-box-probe.json")
	if err := os.WriteFile(sbCfgPath, compiled.Raw, 0o600); err != nil {
		return failAll(err.Error())
	}
	var probeStderr stderrTail
	sbProc, err := spawnRaw("sing-box-probe", sbBin, []string{"run", "-c", sbCfgPath}, probeStderr.Add)
	if err != nil {
		return failAll(err.Error())
	}
	defer terminateAndWait(sbProc, 2*time.Second)

	sandboxClash := clashapi.New(fmt.Sprintf("127.0.0.1:%d", clashPort), clashSecret)
	if err := waitClashReady(ctx, sandboxClash, 5*time.Second, sbProc.doneCh); err != nil {
		if detail := probeStderr.Summary(o.redactString); detail != "" {
			return failAll(fmt.Sprintf("probe sing-box failed: %v (%s)", err, detail))
		}
		return failAll(fmt.Sprintf("probe sing-box failed: %v", err))
	}

	proxiesRes, err := sandboxClash.GetProxies(ctx)
	if err != nil {
		return failAll(err.Error())
	}

	results := make([]ProbeResult, len(nodes))
	var wg sync.WaitGroup
	sem := make(chan struct{}, probeConcurrency)
	for i, n := range nodes {
		i, n := i, n
		tag := sbcfg.NodeTag(n.ID)
		if _, exists := proxiesRes.Proxies[tag]; !exists {
			results[i] = ProbeResult{
				NodeID:    n.ID,
				LatencyMS: -1,
				Error:     fmt.Sprintf("tag %s does not expose Clash delay probing", tag),
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			delay, err := sandboxClash.ProbeDelay(ctx, tag, testURL, timeoutMS)
			if err != nil {
				results[i] = ProbeResult{NodeID: n.ID, LatencyMS: -1, Error: o.redactString(err.Error())}
				return
			}
			results[i] = ProbeResult{NodeID: n.ID, LatencyMS: int64(delay)}
		}()
	}
	wg.Wait()
	return results
}

func (o *Orchestrator) startProcess(core, bin string, args []string) (*managedProc, error) {
	return o.startProcessWithEnv(core, bin, args, nil)
}

func (o *Orchestrator) startProcessWithEnv(core, bin string, args []string, extraEnv []string) (*managedProc, error) {
	return spawnCmdWithEnv(core, bin, args, nil, extraEnv, func(line string) {
		o.AppendLog(core, "", line)
	})
}

func (o *Orchestrator) startProcessWithSudo(core, bin string, args []string, password []byte) (*managedProc, error) {
	pwBuf := make([]byte, len(password)+1)
	copy(pwBuf, password)
	pwBuf[len(password)] = '\n'
	sudoArgs := append([]string{"-S", "-p", "", bin}, args...)
	proc, err := spawnCmd(core, "sudo", sudoArgs, pwBuf, func(line string) {
		o.AppendLog(core, "", line)
	})
	for i := range pwBuf {
		pwBuf[i] = 0
	}
	if err != nil {
		return nil, err
	}
	proc.sudoPass = make([]byte, len(password))
	copy(proc.sudoPass, password)
	return proc, nil
}

func spawnRaw(core, bin string, args []string, onLine func(string)) (*managedProc, error) {
	return spawnCmd(core, bin, args, nil, onLine)
}

func upsertEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func scrubSecretEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "PRISMRAY_BIOMETRIC_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func androidCoreEnv(core string) []string {
	if runtime.GOOS != "android" {
		return nil
	}
	env := scrubSecretEnv(os.Environ())
	env = upsertEnv(env, "GOGC", "200")
	// Explicitly override parent libprismray.so's GOMEMLIMIT=96MiB so sing-box receives
	// 160MiB for geo rule-sets + Tailscale tsnet while Xray stays bounded at 96MiB.
	limit := "160MiB"
	if strings.Contains(strings.ToLower(core), "xray") {
		limit = "96MiB"
	}
	env = upsertEnv(env, "GOMEMLIMIT", limit)
	return env
}

func spawnCmd(core, bin string, args []string, stdinData []byte, onLine func(string)) (*managedProc, error) {
	return spawnCmdWithEnv(core, bin, args, stdinData, nil, onLine)
}

func spawnCmdWithEnv(core, bin string, args []string, stdinData []byte, extraEnv []string, onLine func(string)) (*managedProc, error) {
	cmd := exec.Command(bin, args...)
	env := androidCoreEnv(core)
	if len(env) == 0 {
		env = scrubSecretEnv(os.Environ())
	}
	if len(extraEnv) > 0 {
		env = append(env, extraEnv...)
	}
	cmd.Env = env
	bindParent(cmd)
	var stdinPipe io.WriteCloser
	var err error
	if len(stdinData) > 0 {
		stdinPipe, err = cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		if stdinPipe != nil {
			_ = stdinPipe.Close()
		}
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		if stdinPipe != nil {
			_ = stdinPipe.Close()
		}
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		if stdinPipe != nil {
			_ = stdinPipe.Close()
		}
		return nil, err
	}
	if stdinPipe != nil {
		// Synchronously deliver credentials and close stdin before caller zeroes stdinData,
		// eliminating the Go data race with os/exec's async stdin copy goroutine.
		_, _ = stdinPipe.Write(stdinData)
		_ = stdinPipe.Close()
	}

	var ioWG sync.WaitGroup
	ioWG.Add(2)
	scan := func(r io.Reader) {
		defer ioWG.Done()
		sc := bufio.NewScanner(r)
		buf := make([]byte, 0, 16*1024)
		sc.Buffer(buf, 512*1024)
		for sc.Scan() {
			if onLine != nil {
				onLine(sc.Text())
			}
		}
	}
	go scan(stdout)
	go scan(stderr)

	doneCh := make(chan error, 1)
	go func() {
		ioWG.Wait()
		doneCh <- cmd.Wait()
		close(doneCh)
	}()

	return &managedProc{
		core:   core,
		cmd:    cmd,
		pid:    cmd.Process.Pid,
		doneCh: doneCh,
	}, nil
}

func (o *Orchestrator) watchExit(proc *managedProc, core string) {
	if proc == nil {
		return
	}
	go func() {
		err, ok := <-proc.doneCh
		if !ok && err == nil {
			return
		}
		o.mu.Lock()
		expectedStop := o.stopping
		isCurrent := (core == "sing-box" && o.singBoxProc == proc) || (core == "xray" && o.xrayProc == proc)
		if isCurrent && !expectedStop {
			if core == "sing-box" {
				o.running = false
				o.singBoxProc = nil
				o.tunEnabled = false
				o.clash = nil
			} else {
				o.xrayProc = nil
			}
			if err != nil {
				o.lastError = o.redactString(fmt.Sprintf("%s exited unexpectedly: %v", core, err))
			} else {
				o.lastError = fmt.Sprintf("%s exited unexpectedly", core)
			}
		}
		lastErr := o.lastError
		o.mu.Unlock()

		if isCurrent && !expectedStop {
			o.AppendLog(core, "error", lastErr)
		}
	}()
}

func terminateAndWait(proc *managedProc, grace time.Duration) error {
	if proc == nil || proc.cmd == nil || proc.cmd.Process == nil {
		return nil
	}
	defer func() {
		for i := range proc.sudoPass {
			proc.sudoPass[i] = 0
		}
		proc.sudoPass = nil
	}()
	if err := terminateGracefully(proc.cmd); err != nil && len(proc.sudoPass) > 0 {
		sudoKill(proc.sudoPass, "-TERM", proc.pid)
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-proc.doneCh:
		return err
	case <-timer.C:
		if err := proc.cmd.Process.Kill(); err != nil && len(proc.sudoPass) > 0 {
			sudoKill(proc.sudoPass, "-KILL", proc.pid)
		}
		killTimer := time.NewTimer(5 * time.Second)
		defer killTimer.Stop()
		select {
		case err := <-proc.doneCh:
			return err
		case <-killTimer.C:
			return fmt.Errorf("process pid %d did not exit within 5s after SIGKILL", proc.pid)
		}
	}
}

func sudoKill(password []byte, sig string, pid int) {
	if len(password) == 0 || pid <= 0 {
		return
	}
	buf := make([]byte, len(password)+1)
	copy(buf, password)
	buf[len(password)] = '\n'
	// Terminate both the process group (-pid) and any child sing-box spawned under sudo/env
	// so elevated sing-box never leaks as an orphaned root daemon.
	script := fmt.Sprintf("pkill %s -P %d 2>/dev/null || true; kill %s -- -%d %d 2>/dev/null || true", sig, pid, sig, pid, pid)
	cmd := exec.Command("sudo", "-S", "-p", "", "/bin/sh", "-c", script)
	cmd.Stdin = bytes.NewReader(buf)
	_ = cmd.Run()
	for i := range buf {
		buf[i] = 0
	}
}

func processAlive(proc *managedProc) bool {
	if proc == nil || proc.cmd == nil || proc.cmd.Process == nil {
		return false
	}
	select {
	case <-proc.doneCh:
		return false
	default:
		return true
	}
}

func runPreflight(ctx context.Context, bin string, args []string) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}

func waitPortOrExit(ctx context.Context, port int, timeout time.Duration, doneCh <-chan error) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for {
		select {
		case err := <-doneCh:
			if err != nil {
				return fmt.Errorf("process exited: %w", err)
			}
			return fmt.Errorf("process exited before listening on %s", addr)
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", addr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitClashReady(ctx context.Context, client *clashapi.Client, timeout time.Duration, doneCh <-chan error) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		select {
		case err := <-doneCh:
			if err != nil {
				return fmt.Errorf("sing-box exited: %w", err)
			}
			return fmt.Errorf("sing-box exited before Clash API became ready")
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		pctx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
		_, err := client.GetProxies(pctx)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return fmt.Errorf("Clash API unreachable: %w", lastErr)
		}
		time.Sleep(75 * time.Millisecond)
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func randomHexSecret(nBytes int) string {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func mapXrayLogLevel(sbLevel string) string {
	switch strings.ToLower(strings.TrimSpace(sbLevel)) {
	case "trace", "debug":
		return "debug"
	case "info":
		return "info"
	case "error", "fatal", "panic":
		return "error"
	default:
		return "warning"
	}
}

func (o *Orchestrator) setLastError(msg string) {
	o.mu.Lock()
	o.lastError = msg
	o.mu.Unlock()
}

func buildSecretReplacer(secrets []string) *strings.Replacer {
	if len(secrets) == 0 {
		return nil
	}
	pairs := make([]string, 0, len(secrets)*2)
	for _, sec := range secrets {
		if sec != "" {
			pairs = append(pairs, sec, "[REDACTED]")
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	return strings.NewReplacer(pairs...)
}

func (o *Orchestrator) registerSecrets(in ApplyInput) {
	seen := make(map[string]bool)
	var list []string
	add := func(cand string) {
		if len(cand) >= 4 && !seen[cand] {
			seen[cand] = true
			list = append(list, cand)
		}
	}
	add(in.ClashAPISecret)
	if in.Tailscale != nil {
		add(in.Tailscale.AuthKey)
	}
	for _, l := range in.Listeners {
		if l != nil {
			add(l.Password)
		}
	}
	for _, n := range in.Nodes {
		if n == nil {
			continue
		}
		for _, cand := range []string{
			n.UUID, n.Password, n.PrivateKey, n.PreSharedKey, n.ObfsPassword, n.ShortID, n.VLESSEncryption,
		} {
			add(cand)
		}
	}
	sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) })
	o.secretsMu.Lock()
	o.secrets = list
	o.secretReplacer.Store(buildSecretReplacer(list))
	o.secretsMu.Unlock()
}

func (o *Orchestrator) registerLiteralSecret(s string) {
	if len(s) < 4 {
		return
	}
	o.secretsMu.Lock()
	defer o.secretsMu.Unlock()
	for _, existing := range o.secrets {
		if existing == s {
			return
		}
	}
	o.secrets = append(o.secrets, s)
	sort.Slice(o.secrets, func(i, j int) bool { return len(o.secrets[i]) > len(o.secrets[j]) })
	o.secretReplacer.Store(buildSecretReplacer(o.secrets))
}

var (
	uuidRegex     = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	kvSecretRegex = regexp.MustCompile(`(?i)((?:password|secret|token|private_key|pre_shared_key)=)([^\s&"']+)`)
)

func (o *Orchestrator) redactString(s string) string {
	if repl := o.secretReplacer.Load(); repl != nil {
		s = repl.Replace(s)
	}
	s = uuidRegex.ReplaceAllString(s, "[REDACTED-UUID]")
	s = kvSecretRegex.ReplaceAllString(s, `${1}[REDACTED]`)
	return s
}

func inferLogLevel(msg string) string {
	upper := strings.ToUpper(msg)
	switch {
	case strings.Contains(upper, "FATAL"), strings.Contains(upper, "PANIC"), strings.Contains(upper, "ERROR"), strings.Contains(upper, "[ERR]"):
		return "error"
	case strings.Contains(upper, "WARN"):
		return "warn"
	case strings.Contains(upper, "DEBUG"), strings.Contains(upper, "TRACE"):
		return "debug"
	default:
		return "info"
	}
}

// topologyFingerprint computes a canonical SHA-256 over structural proxy/network state,
// ignoring latency measurements and selector SelectedNodeID so node switches remain hot-swappable.
func topologyFingerprint(in ApplyInput, includeNaive bool) (string, error) {
	type fpGroup struct {
		ID                string
		Strategy          string
		Filter            string
		ToleranceMS       int
		Interval          string
		FailoverTrigger   string
		HighLatencyMS     int
		LoadBalanceShards int
		DetourID          string
		SortOrder         int
		NodeIDs           []string
	}
	nodes := make([]config.Node, 0, len(in.Nodes))
	for _, n := range in.Nodes {
		if n == nil {
			continue
		}
		cp := *n
		cp.Name = ""
		cp.UserAlias = ""
		cp.Favorite = false
		// Preserve only unhealthy (<0) vs healthy (>=0) boolean state so LoadBalance dead-shard
		// eviction triggers a reload while ordinary latency fluctuations remain hot-swappable.
		if cp.Latency < 0 {
			cp.Latency = -1
		} else {
			cp.Latency = 0
		}
		cp.PingMS = 0
		cp.DownSpeedMbps = 0
		cp.UpSpeedMbps = 0
		cp.SubID = ""
		cp.Group = ""
		cp.Tags = nil
		nodes = append(nodes, cp)
	}
	activeLBGroupID := ""
	groups := make([]fpGroup, 0, len(in.Groups))
	for _, g := range in.Groups {
		strat := storage.CanonicalGroupStrategy(g.Strategy)
		if g.ID == in.ActiveGroupID && strat == "loadbalance" {
			activeLBGroupID = g.ID
		}
		groups = append(groups, fpGroup{
			ID:                g.ID,
			Strategy:          strat,
			Filter:            g.Filter,
			ToleranceMS:       g.ToleranceMS,
			Interval:          g.Interval,
			FailoverTrigger:   storage.CanonicalFailoverTrigger(g.FailoverTrigger),
			HighLatencyMS:     g.HighLatencyMS,
			LoadBalanceShards: g.LoadBalanceShards,
			DetourID:          g.DetourID,
			SortOrder:         g.SortOrder,
			NodeIDs:           g.NodeIDs,
		})
	}
	payload := struct {
		Nodes             []config.Node
		Groups            []fpGroup
		Listeners         []*config.ListenConfig
		Routing           ruleset.RoutingProfile
		RuleSets          []ruleset.RuleSetSpec
		ActiveLBGroupID   string
		HighLatencyMS     int
		MixedPort         int
		EnableTUN         bool
		TUNStack          string
		AndroidMode       bool
		ProtectPath       string
		IncludeNaive      bool
		Tailscale         *ruleset.TailscaleConfig
		TailscaleStateDir string
	}{
		Nodes:             nodes,
		Groups:            groups,
		Listeners:         in.Listeners,
		Routing:           in.Routing,
		RuleSets:          in.RuleSets,
		ActiveLBGroupID:   activeLBGroupID,
		HighLatencyMS:     in.HighLatencyMS,
		MixedPort:         in.MixedPort,
		EnableTUN:         in.EnableTUN,
		TUNStack:          in.TUNStack,
		AndroidMode:       in.AndroidMode,
		ProtectPath:       in.ProtectPath,
		IncludeNaive:      includeNaive,
		Tailscale:         in.Tailscale,
		TailscaleStateDir: in.TailscaleStateDir,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

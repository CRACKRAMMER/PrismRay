// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/androiddns"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/api"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/keyring"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/orchestrator"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/install"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/process"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/stats"
)

func resolveRuntimeMode(modeFlag string, desktopFlag bool) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(modeFlag))
	if desktopFlag {
		if mode != "" && mode != authservice.ModeWeb && mode != authservice.ModeDesktop {
			return "", fmt.Errorf("--desktop cannot be combined with --mode=%s", mode)
		}
		mode = authservice.ModeDesktop
	}
	if mode == "" {
		mode = authservice.ModeWeb
	}
	switch mode {
	case authservice.ModeWeb, authservice.ModeDesktop, authservice.ModeAndroid:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported --mode %q (expected web, desktop, or android)", mode)
	}
}

func absCleanPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(p)
}

func resolveDesktopKeyringAccount(mode, dbPath string) string {
	if mode != authservice.ModeDesktop {
		return mode
	}
	if userCfgDir, err := os.UserConfigDir(); err == nil && userCfgDir != "" {
		defaultDB := filepath.Join(userCfgDir, "prismray", "prismray.db")
		if absCleanPath(dbPath) == absCleanPath(defaultDB) {
			return "desktop"
		}
	}
	sum := sha256.Sum256([]byte(absCleanPath(dbPath)))
	return fmt.Sprintf("desktop-%x", sum[:8])
}

func resolveNativeCore(envName string) string {
	nativeDir := strings.TrimSpace(os.Getenv("PRISMRAY_NATIVE_LIB_DIR"))
	if nativeDir == "" {
		return ""
	}
	candidate := filepath.Join(nativeDir, envName)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate
	}
	return ""
}

func isPersistentCoreFile(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" || orchestrator.IsEphemeralMountPath(p) {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func resolveBundledCore(baseName string) string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, symErr := filepath.EvalSymlinks(exePath); symErr == nil {
		exePath = resolved
	}
	exeDir := filepath.Dir(exePath)
	names := []string{baseName}
	if runtime.GOOS == "windows" {
		names = []string{baseName + ".exe", baseName}
	}
	searchDirs := []string{
		exeDir,
		filepath.Join(exeDir, "cores"),
		filepath.Join(exeDir, "..", "lib", "prismray"),
	}
	for _, dir := range searchDirs {
		for _, name := range names {
			candidate := filepath.Join(dir, name)
			if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
				return candidate
			}
		}
	}
	return ""
}

func main() {
	log.SetOutput(os.Stderr)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	configPath := flag.String("config", "settings.json", "Path to configuration file")
	dataDirFlag := flag.String("data-dir", "", "Directory for runtime state, downloaded cores, and rule-sets")
	webDir := flag.String("web-dir", "", "Serve the built Web frontend from this directory (headless mode)")
	desktop := flag.Bool("desktop", false, "Desktop-owned backend; shuts down when stdin closes")
	modeFlag := flag.String("mode", authservice.ModeWeb, "Runtime mode: web | desktop | android")
	repairDB := flag.Bool("repair-db", false, "Verify or salvage desktop database encryption and exit")
	flag.Parse()

	mode, err := resolveRuntimeMode(*modeFlag, *desktop)
	if err != nil {
		slog.Error("invalid startup mode", "err", err)
		os.Exit(1)
	}
	if mode != authservice.ModeWeb && *webDir != "" {
		slog.Error("--web-dir is only valid in web mode", "mode", mode)
		os.Exit(1)
	}

	if mode == authservice.ModeAndroid || runtime.GOOS == "android" {
		androiddns.InstallDefaultResolver()
		slog.Info("installed Android pure-Go DNS resolver", "servers", androiddns.ActiveServers())
	}

	slog.Info("starting PrismRay backend", "version", "1.0.0", "mode", mode)

	cfg, err := appconfig.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "err", err)
		os.Exit(1)
	}
	slog.Info("configuration loaded", "path", *configPath, "listen", cfg.ListenAddr())

	dbPath := cfg.Storage.DatabasePath
	if dbPath == "" {
		dbPath = cfg.Storage.NodesFile
	}
	if dbPath == "" {
		dbPath = "prismray.db"
	}
	if !filepath.IsAbs(dbPath) {
		if cfgDir := filepath.Dir(*configPath); cfgDir != "" && cfgDir != "." {
			dbPath = filepath.Join(cfgDir, dbPath)
		}
	}
	if runtimeDir := strings.TrimSpace(*dataDirFlag); runtimeDir != "" {
		if absRuntime, absErr := filepath.Abs(runtimeDir); absErr == nil {
			runtimeDir = absRuntime
		}
		if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
			slog.Error("failed to create runtime data directory", "dir", runtimeDir, "err", err)
			os.Exit(1)
		}
		cfg.SetRuntimeDir(runtimeDir)
		if !filepath.IsAbs(dbPath) {
			dbPath = filepath.Join(runtimeDir, dbPath)
		}
	}
	if !filepath.IsAbs(dbPath) {
		if absDB, absErr := filepath.Abs(dbPath); absErr == nil {
			dbPath = absDB
		}
	}
	cfg.Storage.DatabasePath = dbPath
	cfg.Storage.NodesFile = dbPath

	if err := api.RecoverBackup(cfg); err != nil {
		slog.Error("backup recovery failed", "err", err)
		os.Exit(1)
	}

	store, err := storage.NewStore(dbPath)
	if err != nil {
		slog.Error("failed to open sqlite store", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer store.Close()
	slog.Info("sqlite database ready", "path", store.Path())

	var storedConfig appconfig.Config
	if found, loadErr := store.GetSetting("app.settings", &storedConfig); loadErr != nil {
		slog.Error("failed to load application settings from sqlite", "err", loadErr)
		os.Exit(1)
	} else if found {
		cfg = appconfig.MergeStored(cfg, &storedConfig)
		if saveErr := store.PutSetting("app.settings", cfg); saveErr != nil {
			slog.Error("failed to synchronize bootstrap settings", "err", saveErr)
			os.Exit(1)
		}
	} else if saveErr := store.PutSetting("app.settings", cfg); saveErr != nil {
		slog.Error("failed to initialize application settings", "err", saveErr)
		os.Exit(1)
	}

	sbCfgPath := cfg.SingBox.ConfigPath
	if !filepath.IsAbs(sbCfgPath) && cfg.RuntimeDir() != "" && cfg.RuntimeDir() != "." {
		sbCfgPath = filepath.Join(cfg.RuntimeDir(), sbCfgPath)
	}

	var kr *keyring.Store
	if mode == authservice.ModeDesktop || mode == authservice.ModeAndroid {
		kr = keyring.New(keyring.Options{
			Service:          "io.prismray.devicekey",
			Account:          resolveDesktopKeyringAccount(mode, store.Path()),
			FallbackPath:     filepath.Join(filepath.Dir(store.Path()), ".device.key"),
			DisableOSKeyring: mode == authservice.ModeAndroid,
		})
	}
	authManager, err := authservice.NewWithOptions(store, authservice.Options{
		Mode:                     mode,
		Keyring:                  kr,
		BootstrapOverride:        os.Getenv("PRISMRAY_BOOTSTRAP_TOKEN"),
		RuntimeSingBoxConfigPath: sbCfgPath,
	})
	if err != nil {
		slog.Error("failed to initialize authentication", "mode", mode, "err", err)
		os.Exit(1)
	}
	if *repairDB {
		slog.Info("database verification/repair complete", "nodes", len(store.List()))
		return
	}

	xrayPath := cfg.Xray.BinaryPath
	if mode == authservice.ModeAndroid || runtime.GOOS == "android" {
		if nativeXray := resolveNativeCore("libxray.so"); nativeXray != "" {
			xrayPath = nativeXray
			_ = store.PutSetting("core.xray.active", nativeXray)
		}
	}
	if xrayPath == "" {
		if nativeXray := resolveNativeCore("libxray.so"); nativeXray != "" {
			xrayPath = nativeXray
		} else {
			var savedXray string
			if found, e := store.GetSetting("core.xray.active", &savedXray); e == nil && found && isPersistentCoreFile(savedXray) {
				xrayPath = savedXray
			} else if bundled := resolveBundledCore("xray"); bundled != "" {
				xrayPath = bundled
			} else if detected, findErr := install.FindXrayBinary(); findErr == nil {
				xrayPath = detected
			} else if detected, findErr := orchestrator.ResolveBinary("xray", "", "PRISMRAY_XRAY_BINARY", "libxray.so"); findErr == nil {
				xrayPath = detected
			} else {
				slog.Warn("xray binary not found yet; coprocessor will be loaded on demand", "err", findErr)
			}
		}
	}
	if mode != authservice.ModeAndroid && runtime.GOOS != "android" && orchestrator.IsEphemeralMountPath(xrayPath) {
		if staged, stageErr := orchestrator.StageEphemeralCore(xrayPath, cfg.DataDir(), "xray"); stageErr == nil {
			slog.Info("staged bundled xray core out of ephemeral AppImage mount", "src", xrayPath, "dst", staged)
			xrayPath = staged
		} else {
			slog.Warn("failed to stage ephemeral xray core; using bundled path", "src", xrayPath, "err", stageErr)
		}
	}

	xrayCfgPath := cfg.Xray.ConfigPath
	if !filepath.IsAbs(xrayCfgPath) && cfg.RuntimeDir() != "" && cfg.RuntimeDir() != "." {
		xrayCfgPath = filepath.Join(cfg.RuntimeDir(), xrayCfgPath)
	}
	pm := process.NewManager(xrayCfgPath)
	pm.SetBinaryPath(xrayPath)
	statsAddr := fmt.Sprintf("127.0.0.1:%d", cfg.Xray.StatsPort)
	statsClient := stats.NewClient(xrayPath, statsAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	server := api.NewServer(pm, store, statsClient, cfg)
	server.SetAuth(authManager)
	server.SetMode(mode)
	server.SetXrayPath(xrayPath)

	singBoxPath := cfg.SingBox.BinaryPath
	if mode == authservice.ModeAndroid || runtime.GOOS == "android" {
		if nativeSB := resolveNativeCore("libsingbox.so"); nativeSB != "" {
			singBoxPath = nativeSB
			_ = store.PutSetting("core.singbox.active", nativeSB)
		}
	}
	if singBoxPath == "" {
		if nativeSB := resolveNativeCore("libsingbox.so"); nativeSB != "" {
			singBoxPath = nativeSB
		} else {
			var saved string
			if found, e := store.GetSetting("core.singbox.active", &saved); e == nil && found && isPersistentCoreFile(saved) {
				singBoxPath = saved
			} else if bundled := resolveBundledCore("sing-box"); bundled != "" {
				singBoxPath = bundled
			} else if detected, e := orchestrator.ResolveBinary("sing-box", "", "PRISMRAY_SINGBOX_BINARY", "libsingbox.so"); e == nil {
				singBoxPath = detected
			} else if detected, e := exec.LookPath("sing-box"); e == nil {
				singBoxPath = detected
			}
		}
	}
	if mode != authservice.ModeAndroid && runtime.GOOS != "android" && orchestrator.IsEphemeralMountPath(singBoxPath) {
		if staged, stageErr := orchestrator.StageEphemeralCore(singBoxPath, cfg.DataDir(), "sing-box"); stageErr == nil {
			slog.Info("staged bundled sing-box core out of ephemeral AppImage mount", "src", singBoxPath, "dst", staged)
			singBoxPath = staged
		} else {
			slog.Warn("failed to stage ephemeral sing-box core; using bundled path", "src", singBoxPath, "err", stageErr)
		}
	}
	server.SetSingBoxPath(singBoxPath)

	effectiveWebDir := strings.TrimSpace(*webDir)
	if mode == authservice.ModeWeb && effectiveWebDir == "" {
		if exePath, exeErr := os.Executable(); exeErr == nil {
			if resolved, symErr := filepath.EvalSymlinks(exePath); symErr == nil {
				exePath = resolved
			}
			candidate := filepath.Join(filepath.Dir(exePath), "web")
			if info, statErr := os.Stat(filepath.Join(candidate, "index.html")); statErr == nil && !info.IsDir() {
				effectiveWebDir = candidate
			}
		}
	}
	if effectiveWebDir != "" {
		if err := server.SetWebDir(effectiveWebDir); err != nil {
			slog.Error("invalid web directory", "dir", effectiveWebDir, "err", err)
			os.Exit(1)
		}
	}

	if mode == authservice.ModeDesktop || mode == authservice.ModeAndroid {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			slog.Error("failed to generate local IPC token", "err", e)
			os.Exit(1)
		}
		server.SetDesktopToken(hex.EncodeToString(b))
		if mode == authservice.ModeAndroid {
			server.SetIPCPath(filepath.Join(filepath.Dir(store.Path()), "runtime-ipc.json"))
		}
	}

	server.SetSettingsPath(*configPath)
	if initialized, _ := authManager.Status(); !initialized {
		slog.Info("first-run web initialization token ready", "bootstrap_token", authManager.BootstrapToken())
	}
	if e := server.RestoreSystemProxy(); e != nil {
		slog.Warn("system proxy recovery", "err", e)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.RestoreLastSession(ctx)
	go server.RunMaintenance(ctx)
	go func() {
		listenAddr := cfg.ListenAddr()
		if mode == authservice.ModeDesktop || mode == authservice.ModeAndroid {
			listenAddr = "127.0.0.1:0"
		}
		if err := server.Start(listenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP control server failed", "err", err)
			os.Exit(1)
		}
	}()

	if *desktop || mode == authservice.ModeDesktop || mode == authservice.ModeAndroid {
		fi, statErr := os.Stdin.Stat()
		if *desktop || (statErr == nil && fi.Mode()&os.ModeNamedPipe != 0) {
			go func() {
				_, _ = io.Copy(io.Discard, os.Stdin)
				select {
				case stop <- os.Interrupt:
				default:
				}
			}()
		}
	}

	<-stop
	cancel()
	slog.Info("shutting down PrismRay backend")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Warn("HTTP shutdown error", "err", err)
	}
	if e := server.ShutdownCleanup(shutdownCtx); e != nil {
		slog.Warn("runtime cleanup error", "err", e)
	}
	statsClient.Stop()
	if err := pm.Stop(); err != nil {
		slog.Warn("xray stop error", "err", err)
	}
}

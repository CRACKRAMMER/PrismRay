// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	runtimeDebug "runtime/debug"
	"strconv"
	"strings"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func initLocalTimezone() {
	if tz := strings.TrimSpace(os.Getenv("TZ")); tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			time.Local = loc
			return
		}
	}
	if rawOff := strings.TrimSpace(os.Getenv("PRISMRAY_TZ_OFFSET_SEC")); rawOff != "" {
		if off, err := strconv.Atoi(rawOff); err == nil && off >= -14*3600 && off <= 14*3600 {
			name := strings.TrimSpace(os.Getenv("PRISMRAY_TZ_NAME"))
			if name == "" {
				sign := "+"
				absOff := off
				if absOff < 0 {
					sign = "-"
					absOff = -absOff
				}
				name = fmt.Sprintf("UTC%s%02d:%02d", sign, absOff/3600, (absOff%3600)/60)
			}
			time.Local = time.FixedZone(name, off)
		}
	}
}

func main() {
	initLocalTimezone()
	stopEarlySig := trapEarlyReloadSignals()
	defer stopEarlySig()

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: sing-box <run|check|version> [-c config.json]\n")
		os.Exit(2)
	}

	// Support global flags before subcommand (e.g. -D dir -c file run) as well as after.
	subcmd, rest := parseSubcommand(os.Args[1:])
	switch subcmd {
	case "version", "-v", "--version":
		printVersion()
	case "check":
		if err := runCheck(rest); err != nil {
			log.Fatal(err)
		}
	case "run":
		if err := runService(rest); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unsupported command %q (expected run, check, or version)\n", subcmd)
		os.Exit(2)
	}
}

func parseSubcommand(args []string) (string, []string) {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			rest := make([]string, 0, len(args)-1)
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+1:]...)
			return a, rest
		}
	}
	return args[0], args[1:]
}

func printVersion() {
	fmt.Printf("sing-box version %s (prismray-core)\n", C.Version)
	fmt.Printf("Environment: go%s %s/%s\n", runtime.Version()[2:], runtime.GOOS, runtime.GOARCH)
	fmt.Println("Tags: with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_tailscale")
}

func parseConfigFlags(args []string) (configPath string, workDir string, disableColor bool, err error) {
	fs := flag.NewFlagSet("sing-box", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&configPath, "c", "config.json", "config path")
	fs.StringVar(&configPath, "config", "config.json", "config path")
	fs.StringVar(&workDir, "D", "", "working directory")
	fs.StringVar(&workDir, "directory", "", "working directory")
	fs.BoolVar(&disableColor, "disable-color", false, "disable color output")
	if err = fs.Parse(args); err != nil {
		return "", "", false, err
	}
	return configPath, workDir, disableColor, nil
}

func baseContext(platform adapter.PlatformInterface) context.Context {
	ctx := include.Context(context.Background())
	if platform != nil {
		ctx = service.ContextWith[adapter.PlatformInterface](ctx, platform)
	}
	return ctx
}

func useAndroidPlatformBridge(protectPath, netIfPath string) bool {
	return runtime.GOOS == "android" || strings.TrimSpace(protectPath) != "" || strings.TrimSpace(netIfPath) != ""
}

func loadOptions(ctx context.Context, path string, disableColor bool, androidBridge bool) (option.Options, error) {
	var raw []byte
	var err error
	if path == "stdin" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return option.Options{}, E.Cause(err, "read config at ", path)
	}
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		return option.Options{}, E.Cause(err, "decode config at ", path)
	}
	if options.Log == nil {
		options.Log = &option.LogOptions{}
	}
	// box.New discards logs when PlatformInterface != nil and Log.Output is empty;
	// force stderr so PrismRay's orchestrator always receives sing-box logs.
	if options.Log.Output == "" {
		options.Log.Output = "stderr"
	}
	if disableColor {
		options.Log.DisableColor = true
	}
	// On Android 14+ with CGO_ENABLED=0, Go's x509.SystemCertPool misses APEX Conscrypt roots
	// (/apex/com.android.conscrypt/cacerts); default to sing-box's embedded Mozilla CA store on Android.
	if androidBridge {
		if options.Certificate == nil {
			options.Certificate = &option.CertificateOptions{}
		}
		if options.Certificate.Store == "" {
			options.Certificate.Store = C.CertificateStoreMozilla
		}
	}
	return options, nil
}

func runCheck(args []string) error {
	cfgPath, workDir, disableColor, err := parseConfigFlags(args)
	if err != nil {
		return err
	}
	if workDir != "" {
		if chErr := os.Chdir(workDir); chErr != nil {
			return chErr
		}
	}
	protectPath := strings.TrimSpace(os.Getenv("PRISMRAY_PROTECT_PATH"))
	netIfPath := strings.TrimSpace(os.Getenv("PRISMRAY_ANDROID_NETIF_PATH"))
	androidBridge := useAndroidPlatformBridge(protectPath, netIfPath)
	var platform adapter.PlatformInterface
	if androidBridge {
		platform = newAndroidPlatform(protectPath, netIfPath)
	}
	ctx, cancel := context.WithCancel(service.ExtendContext(baseContext(platform)))
	defer cancel()

	options, err := loadOptions(ctx, cfgPath, disableColor, androidBridge)
	if err != nil {
		return err
	}
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return err
	}
	_ = instance.Close()
	return nil
}

func runService(args []string) error {
	cfgPath, workDir, disableColor, err := parseConfigFlags(args)
	if err != nil {
		return err
	}
	if workDir != "" {
		if chErr := os.Chdir(workDir); chErr != nil {
			return chErr
		}
	}

	protectPath := strings.TrimSpace(os.Getenv("PRISMRAY_PROTECT_PATH"))
	netIfPath := strings.TrimSpace(os.Getenv("PRISMRAY_ANDROID_NETIF_PATH"))
	tsStatusPath := strings.TrimSpace(os.Getenv("PRISMRAY_TAILSCALE_STATUS_PATH"))
	tsStatusToken := strings.TrimSpace(os.Getenv("PRISMRAY_TAILSCALE_STATUS_TOKEN"))
	_ = os.Unsetenv("PRISMRAY_TAILSCALE_STATUS_TOKEN")
	tsStateDir := strings.TrimSpace(os.Getenv("PRISMRAY_TAILSCALE_STATE_DIR"))
	cacheDBPath := strings.TrimSpace(os.Getenv("PRISMRAY_CACHE_DB_PATH"))
	ctrlAddr := strings.TrimSpace(os.Getenv("PRISMRAY_CORE_CTRL_ADDR"))
	ctrlToken := strings.TrimSpace(os.Getenv("PRISMRAY_CORE_CTRL_TOKEN"))
	_ = os.Unsetenv("PRISMRAY_CORE_CTRL_TOKEN")
	if tokenFile := strings.TrimSpace(os.Getenv("PRISMRAY_CORE_CTRL_TOKEN_FILE")); tokenFile != "" {
		_ = os.Unsetenv("PRISMRAY_CORE_CTRL_TOKEN_FILE")
		if raw, rErr := os.ReadFile(tokenFile); rErr == nil {
			if tok := strings.TrimSpace(string(raw)); tok != "" {
				ctrlToken = tok
			}
		}
		_ = os.Remove(tokenFile)
	}

	androidBridge := useAndroidPlatformBridge(protectPath, netIfPath)

	osSignals := make(chan os.Signal, 2)
	signal.Notify(osSignals, serviceSignals()...)
	defer signal.Stop(osSignals)

	for {
		var platform adapter.PlatformInterface
		if androidBridge {
			platform = newAndroidPlatform(protectPath, netIfPath)
		}
		ctx, cancel := context.WithCancel(service.ExtendContext(baseContext(platform)))
		options, loadErr := loadOptions(ctx, cfgPath, disableColor, androidBridge)
		if loadErr != nil {
			cancel()
			return loadErr
		}
		instance, newErr := box.New(box.Options{
			Context: ctx,
			Options: options,
		})
		if newErr != nil {
			cancel()
			return E.Cause(newErr, "create service")
		}

		startDone := make(chan struct{})
		go func() {
			select {
			case <-startDone:
			case sig := <-osSignals:
				cancel()
				_ = instance.Close()
				// Re-deliver signal so outer loop exits cleanly.
				select {
				case osSignals <- sig:
				default:
				}
			}
		}()

		startErr := instance.Start()
		close(startDone)
		if startErr != nil {
			cancel()
			_ = instance.Close()
			return E.Cause(startErr, "start service")
		}
		stopTailscaleRuntime := startTailscaleRuntime(ctx, instance, tsStatusPath, tsStatusToken, ctrlAddr, ctrlToken)
		if cacheDBPath != "" {
			chownPathToSudoInvoker(cacheDBPath)
		}
		runtimeDebug.FreeOSMemory()

		sig := <-osSignals
		cancel()
		stopTailscaleRuntime()
		if tsStatusPath != "" && !isReloadSignal(sig) {
			_ = os.Remove(tsStatusPath)
		}
		if tsStateDir != "" {
			chownTreeToSudoInvoker(tsStateDir)
		}
		if cacheDBPath != "" {
			chownPathToSudoInvoker(cacheDBPath)
		}
		closeDone := make(chan struct{})
		go func() {
			select {
			case <-closeDone:
			case <-time.After(C.FatalStopTimeout):
				log.Fatal("sing-box did not close!")
			}
		}()
		closeErr := instance.Close()
		close(closeDone)
		if tsStateDir != "" {
			chownTreeToSudoInvoker(tsStateDir)
		}
		if cacheDBPath != "" {
			chownPathToSudoInvoker(cacheDBPath)
		}
		if !isReloadSignal(sig) {
			if closeErr != nil {
				log.Error(E.Cause(closeErr, "sing-box did not close properly"))
			}
			return nil
		}
	}
}

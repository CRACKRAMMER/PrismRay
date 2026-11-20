// SPDX-License-Identifier: MPL-2.0
package tun

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTunnelExcludesProxyAndCapturesDNS(t *testing.T) {
	b, e := Generate(10808, []net.IP{net.ParseIP("203.0.113.7"), net.ParseIP("2001:db8::7")})
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Inbounds []struct {
			Exclude []string `json:"route_exclude_address"`
		}
		Route struct {
			Rules []struct {
				Action string `json:"action"`
				Port   int    `json:"port"`
			}
		}
	}
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	if len(c.Inbounds[0].Exclude) != 4 || c.Route.Rules[0].Action != "hijack-dns" || c.Route.Rules[0].Port != 53 {
		t.Fatal("missing loop exclusion or DNS route")
	}
	if runtime.GOOS == "linux" {
		var options struct {
			Inbounds []struct {
				InterfaceName string `json:"interface_name"`
				TableIndex    int    `json:"iproute2_table_index"`
				RuleIndex     int    `json:"iproute2_rule_index"`
				FallbackIndex int    `json:"auto_redirect_iproute2_fallback_rule_index"`
				InputMark     string `json:"auto_redirect_input_mark"`
				OutputMark    string `json:"auto_redirect_output_mark"`
				ResetMark     string `json:"auto_redirect_reset_mark"`
				NFQueue       int    `json:"auto_redirect_nfqueue"`
			}
		}
		if err := json.Unmarshal(b, &options); err != nil {
			t.Fatal(err)
		}
		inbound := options.Inbounds[0]
		if inbound.InterfaceName != "prismray0" || inbound.TableIndex != 2178 || inbound.RuleIndex != 7000 || inbound.FallbackIndex != 32778 || inbound.InputMark != "0x21781" || inbound.OutputMark != "0x21782" || inbound.ResetMark != "0x21783" || inbound.NFQueue != 2178 {
			t.Fatalf("TUN did not isolate Linux routing resources: %+v", inbound)
		}
	}
	if _, e = Generate(10808, nil); e == nil {
		t.Fatal("accepted missing server IP")
	}
}

func TestLinuxRouteSpaceDetectsOnlyPrismRayConflicts(t *testing.T) {
	existingRoutes := []byte(`[{"dst":"default","table":"2022"}]`)
	existingRules := []byte(`[{"priority":9000},{"priority":5210}]`)
	if err := checkRouteSpace(existingRoutes, existingRules); err != nil {
		t.Fatal(err)
	}
	if err := checkRouteSpace([]byte(`[{"dst":"default","table":"2178"}]`), existingRules); err == nil || !strings.Contains(err.Error(), "2178") {
		t.Fatalf("did not detect route table collision: %v", err)
	}
	if err := checkRouteSpace(existingRoutes, []byte(`[{"priority":7002}]`)); err == nil || !strings.Contains(err.Error(), "7002") {
		t.Fatalf("did not detect rule collision: %v", err)
	}
}

func TestCommandFailureKeepsFatalRouteError(t *testing.T) {
	output := "+0800 INFO network: updated interface\n\x1b[31mFATAL\x1b[0m start service: add route 29: file exists\n"
	if got := commandFailure(nil, output); got != "FATAL start service: add route 29: file exists" {
		t.Fatalf("unexpected diagnostic: %q", got)
	}
}

func TestStartReportsSingBoxDiagnostic(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	binary := filepath.Join(t.TempDir(), "sing-box")
	script := "#!/bin/sh\nif [ \"$1\" = check ]; then exit 0; fi\necho 'permission denied by fixture' >&2\nexit 1\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{
		CheckRouteConflict: func(context.Context) error { return nil },
	}
	err := manager.StartWithPassword(binary, filepath.Join(t.TempDir(), "tun.json"), []byte(`{}`), nil)
	if err == nil || !strings.Contains(err.Error(), "permission denied by fixture") {
		t.Fatalf("unexpected error: %v", err)
	}
}

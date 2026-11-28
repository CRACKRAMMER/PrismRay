// SPDX-License-Identifier: MPL-2.0
package tun

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/fileutil"
)

type Manager struct {
	cmd                *exec.Cmd
	done               chan struct{}
	err                error
	CheckRouteConflict func(context.Context) error
}

const (
	linuxRouteTableIndex = 2178
	linuxRuleStartIndex  = 7000
	linuxFallbackIndex   = 32778
)

type cappedBuffer struct {
	data  []byte
	limit int
}

var ansiControl = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func (b *cappedBuffer) Write(p []byte) (int, error) {
	written := len(p)
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return written, nil
}

func commandFailure(err error, output string) string {
	if detail := strings.TrimSpace(ansiControl.ReplaceAllString(output, "")); detail != "" {
		lastFailure := ""
		for _, line := range strings.Split(detail, "\n") {
			if strings.Contains(line, "FATAL") || strings.Contains(line, "ERROR") {
				lastFailure = strings.TrimSpace(line)
			}
		}
		if lastFailure != "" {
			return lastFailure
		}
		return detail
	}
	if err != nil {
		return err.Error()
	}
	return "进程意外退出"
}

func (m *Manager) Running() bool {
	if m.cmd == nil {
		return false
	}
	select {
	case <-m.done:
		return false
	default:
		return true
	}
}
func Generate(port int, ips []net.IP) ([]byte, error) {
	return GenerateWithLogLevel(port, ips, "warning")
}

func GenerateWithLogLevel(port int, ips []net.IP, logLevel string) ([]byte, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("proxy server IP is required")
	}
	excluded := []string{"127.0.0.0/8", "::1/128"}
	for _, ip := range ips {
		if ip.To4() != nil {
			excluded = append(excluded, ip.String()+"/32")
		} else {
			excluded = append(excluded, ip.String()+"/128")
		}
	}
	if logLevel == "warning" {
		logLevel = "warn"
	}
	if logLevel != "error" && logLevel != "warn" && logLevel != "info" && logLevel != "debug" {
		logLevel = "info"
	}
	inbound := map[string]interface{}{"type": "tun", "tag": "tun-in", "address": []string{"172.29.255.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 1500, "auto_route": true, "auto_redirect": true, "strict_route": true, "route_exclude_address": excluded}
	if runtime.GOOS == "linux" {
		// These must not overlap the sing-box defaults (table 2022, rules 9000+):
		// another TUN on the host may already own those routes and firewall marks.
		inbound["interface_name"] = "prismray0"
		inbound["iproute2_table_index"] = linuxRouteTableIndex
		inbound["iproute2_rule_index"] = linuxRuleStartIndex
		inbound["auto_redirect_iproute2_fallback_rule_index"] = linuxFallbackIndex
		inbound["auto_redirect_input_mark"] = "0x21781"
		inbound["auto_redirect_output_mark"] = "0x21782"
		inbound["auto_redirect_reset_mark"] = "0x21783"
		inbound["auto_redirect_nfqueue"] = 2178
	}
	return json.MarshalIndent(map[string]interface{}{"log": map[string]interface{}{"level": logLevel, "timestamp": true}, "inbounds": []interface{}{inbound}, "outbounds": []interface{}{map[string]interface{}{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": port, "version": "5"}}, "dns": map[string]interface{}{"servers": []interface{}{map[string]interface{}{"type": "https", "tag": "secure-dns", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": "proxy"}}, "final": "secure-dns"}, "route": map[string]interface{}{"auto_detect_interface": true, "rules": []interface{}{map[string]interface{}{"port": 53, "action": "hijack-dns"}}, "final": "proxy"}}, "", "  ")
}
func (m *Manager) Start(binary, path string, b []byte) error {
	return m.StartWithPassword(binary, path, b, nil)
}

func (m *Manager) StartWithPassword(binary, path string, b, password []byte) error {
	if m.Running() {
		return fmt.Errorf("TUN already running")
	}
	if e := fileutil.WritePrivate(path, b); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, e := exec.CommandContext(ctx, binary, "check", "-c", path).CombinedOutput(); e != nil {
		return fmt.Errorf("sing-box 配置检查失败：%s", commandFailure(e, string(output)))
	}
	if m.CheckRouteConflict != nil {
		if err := m.CheckRouteConflict(ctx); err != nil {
			return err
		}
	} else if runtime.GOOS == "linux" {
		if err := checkLinuxRouteAvailability(ctx); err != nil {
			return err
		}
	}
	cmd := exec.Command(binary, "run", "-c", path)
	var credentialInput []byte
	var stdinPipe io.WriteCloser
	if len(password) > 0 {
		cmd = exec.Command("sudo", "-S", "-p", "", "--", binary, "run", "-c", path)
		credentialInput = append(append([]byte(nil), password...), '\n')
		var pErr error
		stdinPipe, pErr = cmd.StdinPipe()
		if pErr != nil {
			for i := range credentialInput {
				credentialInput[i] = 0
			}
			return pErr
		}
	}
	diagnostic := &cappedBuffer{limit: 16 << 10}
	cmd.Stderr = io.MultiWriter(os.Stderr, diagnostic)
	if e := cmd.Start(); e != nil {
		if stdinPipe != nil {
			_ = stdinPipe.Close()
		}
		for i := range credentialInput {
			credentialInput[i] = 0
		}
		return e
	}
	if stdinPipe != nil {
		_, _ = stdinPipe.Write(credentialInput)
		_ = stdinPipe.Close()
		for i := range credentialInput {
			credentialInput[i] = 0
		}
	}
	m.cmd = cmd
	m.done = make(chan struct{})
	go func() { m.err = cmd.Wait(); close(m.done) }()
	select {
	case <-m.done:
		return fmt.Errorf("TUN 进程启动后退出：%s", commandFailure(m.err, string(diagnostic.data)))
	case <-time.After(time.Second):
		return nil
	}
}
func (m *Manager) Stop() error {
	if !m.Running() {
		return nil
	}
	if e := m.cmd.Process.Signal(os.Interrupt); e != nil {
		_ = m.cmd.Process.Kill()
	}
	select {
	case <-m.done:
		return nil
	case <-time.After(5 * time.Second):
		_ = m.cmd.Process.Kill()
		<-m.done
		return fmt.Errorf("TUN 被强制停止，请检查系统路由是否已恢复")
	}
}

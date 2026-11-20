// SPDX-License-Identifier: MPL-2.0

package tun

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
)

// checkLinuxRouteAvailability leaves routes owned by other VPNs untouched.
// iproute2 is used only for a read-only preflight; sing-box manages its routes.
func checkLinuxRouteAvailability(ctx context.Context) error {
	if _, err := exec.LookPath("ip"); err != nil {
		return nil
	}
	for _, family := range []string{"-4", "-6"} {
		routes, err := exec.CommandContext(ctx, "ip", "-j", family, "route", "show", "table", "all").CombinedOutput()
		if err != nil {
			return fmt.Errorf("无法检查 Linux 路由表：%s", commandFailure(err, string(routes)))
		}
		rules, err := exec.CommandContext(ctx, "ip", "-j", family, "rule", "show").CombinedOutput()
		if err != nil {
			return fmt.Errorf("无法检查 Linux 路由规则：%s", commandFailure(err, string(rules)))
		}
		if err := checkRouteSpace(routes, rules); err != nil {
			return err
		}
	}
	return nil
}

func checkRouteSpace(routes, rules []byte) error {
	var entries []struct {
		Table json.RawMessage `json:"table"`
	}
	if err := json.Unmarshal(routes, &entries); err != nil {
		return fmt.Errorf("解析 Linux 路由表失败：%w", err)
	}
	for _, entry := range entries {
		var table string
		if err := json.Unmarshal(entry.Table, &table); err != nil {
			var number int
			if json.Unmarshal(entry.Table, &number) == nil {
				table = strconv.Itoa(number)
			}
		}
		if table == strconv.Itoa(linuxRouteTableIndex) {
			return fmt.Errorf("TUN 路由表 %d 已被其他进程占用，请先关闭冲突的 TUN/VPN", linuxRouteTableIndex)
		}
	}
	var priorities []struct {
		Priority int `json:"priority"`
	}
	if err := json.Unmarshal(rules, &priorities); err != nil {
		return fmt.Errorf("解析 Linux 路由规则失败：%w", err)
	}
	for _, rule := range priorities {
		if rule.Priority >= linuxRuleStartIndex && rule.Priority <= linuxRuleStartIndex+32 || rule.Priority == linuxFallbackIndex {
			return fmt.Errorf("TUN 路由规则 %d 已被其他进程占用，请先关闭冲突的 TUN/VPN", rule.Priority)
		}
	}
	return nil
}

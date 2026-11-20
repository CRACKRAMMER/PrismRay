// SPDX-License-Identifier: MPL-2.0
package systemproxy

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
)

func (m *Manager) lookBinary(name string) bool {
	lp := m.lookPathFn()
	_, err := lp(name)
	return err == nil
}

func gnomeProxySettings(port int) []Setting {
	var settings []Setting
	// GNOME uses GVariant values, kept verbatim for exact restoration.
	for _, proto := range []string{"http", "https", "socks"} {
		schema := "org.gnome.system.proxy." + proto
		settings = append(settings,
			Setting{Read: []string{"gsettings", "get", schema, "host"}, Write: []string{"gsettings", "set", schema, "host"}, Proxy: "'127.0.0.1'"},
			Setting{Read: []string{"gsettings", "get", schema, "port"}, Write: []string{"gsettings", "set", schema, "port"}, Proxy: fmt.Sprint(port)},
		)
	}
	settings = append(settings, Setting{
		Read:  []string{"gsettings", "get", "org.gnome.system.proxy", "mode"},
		Write: []string{"gsettings", "set", "org.gnome.system.proxy", "mode"},
		Proxy: "'manual'",
	})
	return settings
}

func (m *Manager) resolveKDETools() (string, string, string, error) {
	has6 := m.lookBinary("kreadconfig6") && m.lookBinary("kwriteconfig6")
	has5 := m.lookBinary("kreadconfig5") && m.lookBinary("kwriteconfig5")
	if os.Getenv("KDE_SESSION_VERSION") == "6" && has6 {
		reload := ""
		if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" || m.Run != nil {
			switch {
			case m.lookBinary("dbus-send"):
				reload = "dbus-send"
			case m.lookBinary("qdbus6"):
				reload = "qdbus6"
			case m.lookBinary("qdbus"):
				reload = "qdbus"
			}
		}
		return "kreadconfig6", "kwriteconfig6", reload, nil
	}
	if has6 {
		reload := ""
		if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" || m.Run != nil {
			switch {
			case m.lookBinary("dbus-send"):
				reload = "dbus-send"
			case m.lookBinary("qdbus6"):
				reload = "qdbus6"
			}
		}
		return "kreadconfig6", "kwriteconfig6", reload, nil
	}
	if has5 {
		reload := ""
		if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" || m.Run != nil {
			switch {
			case m.lookBinary("dbus-send"):
				reload = "dbus-send"
			case m.lookBinary("qdbus"):
				reload = "qdbus"
			}
		}
		return "kreadconfig5", "kwriteconfig5", reload, nil
	}
	return "", "", "", fmt.Errorf("未找到 kwriteconfig6 / kwriteconfig5，请先安装 KDE 配置工具或在系统设置中手动配置代理")
}

func (m *Manager) kdeSettings(port int) ([]Setting, error) {
	readCmd, writeCmd, reloadCmd, err := m.resolveKDETools()
	if err != nil {
		return nil, err
	}
	cfgFile := strings.TrimSpace(m.ConfigFile)
	if cfgFile == "" {
		cfgFile = "kioslaverc"
	}

	httpURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	socksURL := fmt.Sprintf("socks://127.0.0.1:%d", port)
	noProxy := "localhost,127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

	entries := []struct {
		key        string
		proxyValue string
		defRead    string
	}{
		{key: "httpProxy", proxyValue: httpURL},
		{key: "httpsProxy", proxyValue: httpURL},
		{key: "ftpProxy", proxyValue: httpURL},
		{key: "socksProxy", proxyValue: socksURL},
		{key: "NoProxyFor", proxyValue: noProxy},
		{key: "ProxyType", proxyValue: "1", defRead: "0"},
	}

	settings := make([]Setting, 0, len(entries)+8)
	for _, entry := range entries {
		readArgs := []string{readCmd, "--file", cfgFile, "--group", "Proxy Settings", "--key", entry.key}
		if entry.defRead != "" {
			readArgs = append(readArgs, "--default", entry.defRead)
		}
		writeArgs := []string{writeCmd, "--file", cfgFile, "--group", "Proxy Settings", "--key", entry.key}
		settings = append(settings, Setting{
			Read:  readArgs,
			Write: writeArgs,
			Proxy: entry.proxyValue,
		})
	}

	// Sync org.gnome.system.proxy too if gsettings schema exists so GTK/Chromium apps follow KDE System Proxy.
	if m.lookBinary("gsettings") {
		if _, err := m.run([]string{"gsettings", "get", "org.gnome.system.proxy", "mode"}); err == nil {
			settings = append(settings, gnomeProxySettings(port)...)
		}
	}

	switch reloadCmd {
	case "dbus-send":
		args := []string{"dbus-send", "--session", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:"}
		settings = append(settings, Setting{ApplyArgs: args, RestoreArgs: args})
	case "qdbus6", "qdbus":
		args := []string{reloadCmd, "org.kde.klauncher6", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", ""}
		if reloadCmd == "qdbus" {
			args[1] = "org.kde.klauncher5"
		}
		settings = append(settings, Setting{ApplyArgs: args, RestoreArgs: args})
	}
	return settings, nil
}

func (m *Manager) macSettings(port int) ([]Setting, error) {
	services, e := m.run([]string{"networksetup", "-listallnetworkservices"})
	if e != nil {
		return nil, e
	}
	settings := []Setting{}
	for _, service := range strings.Split(services, "\n")[1:] {
		if service == "" || strings.HasPrefix(service, "*") {
			continue
		}
		for _, kind := range []string{"webproxy", "securewebproxy"} {
			out, e := m.run([]string{"networksetup", "-get" + kind, service})
			if e != nil {
				return nil, e
			}
			values := map[string]string{}
			for _, line := range strings.Split(out, "\n") {
				k, v, ok := strings.Cut(line, ": ")
				if ok {
					values[k] = v
				}
			}
			if values["Authenticated Proxy Enabled"] == "1" {
				return nil, fmt.Errorf("服务 %s 使用认证代理，无法安全备份密码", service)
			}
			host := values["Server"]
			oldPort := values["Port"]
			if oldPort == "" {
				oldPort = "0"
			}
			state := "off"
			if values["Enabled"] == "Yes" {
				state = "on"
			}
			// Restored in reverse: endpoint first, then its original enabled flag.
			settings = append(settings, Setting{RestoreArgs: []string{"networksetup", "-set" + kind + "state", service, state}, ApplyArgs: []string{"networksetup", "-set" + kind, service, "127.0.0.1", fmt.Sprint(port)}}, Setting{RestoreArgs: []string{"networksetup", "-set" + kind, service, host, oldPort}, ApplyArgs: []string{"networksetup", "-set" + kind + "state", service, "on"}})
		}
	}
	if len(settings) == 0 {
		return nil, fmt.Errorf("no active network services")
	}
	return settings, nil
}
func powershell(script string) []string {
	words := utf16.Encode([]rune(script))
	b := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(b[i*2:], w)
	}
	return []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b)}
}
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

const proxyRegistry = `HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
const refreshInternet = `;Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class PrismRayWinInet { [DllImport("wininet.dll")] public static extern bool InternetSetOption(IntPtr h,int option,IntPtr buffer,int length); }';[PrismRayWinInet]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)|Out-Null;[PrismRayWinInet]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)|Out-Null`

func (m *Manager) windowsSettings(port int) ([]Setting, error) {
	read := `$ErrorActionPreference='Stop';$p=Get-ItemProperty -LiteralPath ` + psQuote(proxyRegistry) + `;@{enable=$p.ProxyEnable;server=$p.ProxyServer;override=$p.ProxyOverride}|ConvertTo-Json -Compress`
	raw, e := m.run(powershell(read))
	if e != nil {
		return nil, e
	}
	var old map[string]interface{}
	if e = json.Unmarshal([]byte(raw), &old); e != nil {
		return nil, e
	}
	restore := `$ErrorActionPreference='Stop';$p=` + psQuote(proxyRegistry) + `;`
	for key, name := range map[string]string{"enable": "ProxyEnable", "server": "ProxyServer", "override": "ProxyOverride"} {
		v := old[key]
		if v == nil {
			restore += `Remove-ItemProperty -LiteralPath $p -Name ` + name + ` -ErrorAction SilentlyContinue;`
		} else if key == "enable" {
			number, ok := v.(float64)
			if !ok {
				return nil, fmt.Errorf("invalid Windows proxy flag")
			}
			restore += fmt.Sprintf(`Set-ItemProperty -LiteralPath $p -Name %s -Value %d;`, name, int(number))
		} else {
			str, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("invalid Windows proxy value")
			}
			restore += `Set-ItemProperty -LiteralPath $p -Name ` + name + ` -Value ` + psQuote(str) + `;`
		}
	}
	apply := `$ErrorActionPreference='Stop';$p=` + psQuote(proxyRegistry) + `;Set-ItemProperty -LiteralPath $p -Name ProxyServer -Value ` + psQuote(fmt.Sprintf("http=127.0.0.1:%d;https=127.0.0.1:%d", port, port)) + `;Set-ItemProperty -LiteralPath $p -Name ProxyOverride -Value '<local>';Set-ItemProperty -LiteralPath $p -Name ProxyEnable -Value 1`
	return []Setting{{RestoreArgs: powershell(restore + refreshInternet), ApplyArgs: powershell(apply + refreshInternet)}}, nil
}

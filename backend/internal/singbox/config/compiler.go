// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

const (
	// LinuxAutoRedirectOutputMark matches tun.auto_redirect_output_mark used by sing-box on Linux.
	LinuxAutoRedirectOutputMark uint32 = 0x21782
	// BlockOutboundTag identifies the fail-closed block outbound used by Kill Switch.
	BlockOutboundTag = "block-out"
	// MaxLoadBalanceShards caps simultaneous load-balance exit shards to curb battery/CPU overhead.
	MaxLoadBalanceShards = 4
	// AndroidAppInboundTag identifies the authenticated loopback SOCKS5 inbound used for Android per-app rules.
	AndroidAppInboundTag = "android-app-in"
	// AndroidAppOtherUser is the fallback SOCKS5 username for Android apps not matching any watched package rule.
	AndroidAppOtherUser = "__other__"
)

// CompileInput holds the complete state required to compile a sing-box 1.14+ configuration.
type CompileInput struct {
	Nodes                 []*config.Node
	Groups                []storage.Group
	Listeners             []*config.ListenConfig
	Routing               ruleset.RoutingProfile
	RuleSets              []ruleset.RuleSetSpec
	ActiveNodeID          string
	ActiveGroupID         string
	MixedPort             int
	ClashAPIPort          int
	ClashAPISecret        string
	EnableTUN             bool
	TUNStack              string // mixed | system | gvisor
	AndroidMode           bool
	ProtectPath           string
	AndroidAppSocksPort   int
	AndroidAppSocksSecret string
	AndroidAppPackages    []string
	DefaultMark           uint32
	XrayBridgePorts       map[string]int // node.ID -> loopback SOCKS5 port on 127.0.0.1
	IncludeNaive          bool
	ForceRemoteRules      bool
	CacheFilePath         string
}

// CompileOutput holds the generated JSON bytes alongside structural diagnostics.
type CompileOutput struct {
	Raw          []byte
	ActiveTag    string
	IncludedTags map[string]bool
	SkippedNaive []string
}

// CronetAvailable checks whether libcronet shared library exists alongside sing-box
// or in common system library locations so naive outbounds do not crash sing-box.
func CronetAvailable(singBoxBinary string) bool {
	if singBoxBinary != "" {
		dir := filepath.Dir(singBoxBinary)
		for _, candidate := range []string{"libcronet.so", "libcronet.dylib", "cronet.dll"} {
			if st, err := os.Stat(filepath.Join(dir, candidate)); err == nil && !st.IsDir() {
				return true
			}
		}
	}
	if _, err := exec.LookPath("libcronet.so"); err == nil {
		return true
	}
	for _, p := range []string{"/usr/lib/libcronet.so", "/usr/local/lib/libcronet.so"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

// NodeTag returns the deterministic sing-box outbound/endpoint tag for a node ID.
func NodeTag(id string) string { return "node-" + id }

// GroupTag returns the deterministic sing-box selector/urltest tag for a group ID.
func GroupTag(id string) string { return "group-" + id }

// GroupAutoTag returns the internal urltest/failover auto-selection outbound tag wrapped by GroupTag.
func GroupAutoTag(id string) string { return "group-" + id + "-auto" }

// GroupScopedNodeTag returns the scoped sing-box outbound tag used when a member node
// is dialed through a policy group that configures its own detour relay.
func GroupScopedNodeTag(nodeID, groupID string) string {
	return NodeTag(nodeID) + "--via-" + groupID
}

// ValidateGroupInterval ensures an optional group probe interval parses cleanly for sing-box.
func ValidateGroupInterval(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fmt.Errorf("测速间隔格式无效 %q（请使用如 1m、5m、30s 的 Go 时间格式）", raw)
	}
	return nil
}

// normalizeGroupTiming sanitizes urltest/failover interval and tolerance values so sing-box
// never exits at startup (e.g. missing duration unit, tolerance > uint16, or interval > idle_timeout).
func normalizeGroupTiming(rawInterval, defaultInterval string, rawTol, defaultTol int) (interval, idleTimeout string, tol int) {
	s := strings.TrimSpace(rawInterval)
	if s == "" {
		s = defaultInterval
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		// Gracefully recover legacy numeric-only minutes like "5" -> "5m".
		if mins, nErr := strconv.Atoi(s); nErr == nil && mins > 0 {
			d = time.Duration(mins) * time.Minute
			s = d.String()
		} else {
			d, _ = time.ParseDuration(defaultInterval)
			if d <= 0 {
				d = 5 * time.Minute
			}
			s = d.String()
		}
	}
	const defaultIdleTimeout = 30 * time.Minute
	if d > defaultIdleTimeout {
		idle := d * 2
		if idle < d {
			idle = d
		}
		idleTimeout = idle.String()
	}
	tol = rawTol
	if tol <= 0 {
		tol = defaultTol
	}
	if tol > 65535 {
		tol = 65535
	}
	return s, idleTimeout, tol
}

const maxDetourChainDepth = 8

func validateDetourGraph(
	startKind string, // "node" | "group"
	startID string,
	detourID string,
	nodes []*config.Node,
	groups []storage.Group,
) error {
	detourID = strings.TrimSpace(detourID)
	if detourID == "" {
		return nil
	}
	startID = strings.TrimSpace(startID)
	if startID != "" && detourID == startID {
		if startKind == "group" {
			return fmt.Errorf("策略分组前置中转不能指向分组自身")
		}
		return fmt.Errorf("前置中转不能指向节点自身")
	}

	nodeMap := make(map[string]*config.Node, len(nodes))
	for _, n := range nodes {
		if n != nil && n.ID != "" {
			nodeMap[n.ID] = n
		}
	}
	if startKind == "node" {
		if self := nodeMap[startID]; self != nil && self.RequiresXray() {
			return fmt.Errorf("Xray 专属协议暂不支持作为链式落地节点（可作为前置中转，或使用 sing-box 原生协议作为落地）")
		}
	}

	groupMap := make(map[string]storage.Group, len(groups))
	for _, g := range groups {
		if g.ID != "" {
			groupMap[g.ID] = g
		}
	}

	if g, ok := groupMap[detourID]; ok {
		if storage.CanonicalGroupStrategy(g.Strategy) == "loadbalance" {
			return fmt.Errorf("负载均衡分组 %q 不可作为前置中转，请选择自动测速 / 故障切换 / 手动选择分组或单节点", g.Name)
		}
	} else if _, ok := nodeMap[detourID]; !ok {
		return fmt.Errorf("前置中转目标 %q 不存在", detourID)
	}

	// Walk all reachable dependencies (including 3-hop group.DetourID -> member.DetourID -> member)
	// starting from the candidate target to ensure no cycle can return to startID or any ancestor.
	visNodes := map[string]bool{}
	visGroups := map[string]bool{}
	if startID != "" {
		if startKind == "node" {
			visNodes[startID] = true
		} else if startKind == "group" {
			visGroups[startID] = true
		}
	}

	var walkTarget func(targetID string, depth int) error
	walkTarget = func(targetID string, depth int) error {
		targetID = strings.TrimSpace(targetID)
		if targetID == "" {
			return nil
		}
		if depth > maxDetourChainDepth {
			return fmt.Errorf("链式代理层级过深（最多 %d 层）或存在环路", maxDetourChainDepth)
		}
		if g, isGroup := groupMap[targetID]; isGroup {
			if storage.CanonicalGroupStrategy(g.Strategy) == "loadbalance" {
				return fmt.Errorf("链式路径包含不支持的负载均衡分组 %q", g.Name)
			}
			if visGroups[g.ID] {
				return fmt.Errorf("链式代理存在策略分组循环依赖 (%s)", g.Name)
			}
			visGroups[g.ID] = true
			defer delete(visGroups, g.ID)
			if gDetour := strings.TrimSpace(g.DetourID); gDetour != "" {
				if err := walkTarget(gDetour, depth+1); err != nil {
					return err
				}
			}
			for _, mid := range g.NodeIDs {
				if startKind == "node" && startID != "" && mid == startID {
					return fmt.Errorf("前置策略分组 %q 包含当前落地节点自身，会形成循环代理", g.Name)
				}
				if err := walkTarget(mid, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if visNodes[targetID] {
			return fmt.Errorf("前置中转链路存在循环依赖，禁止保存")
		}
		n := nodeMap[targetID]
		if n == nil {
			return nil
		}
		visNodes[targetID] = true
		defer delete(visNodes, targetID)
		if next := strings.TrimSpace(n.DetourID); next != "" {
			return walkTarget(next, depth+1)
		}
		return nil
	}

	// For a policy group G with G.DetourID, also verify that G.DetourID is not one of G's own
	// member nodes (or reachable from G.DetourID back into G's members creating a 3-hop loop).
	if startKind == "group" {
		if selfG, ok := groupMap[startID]; ok {
			memberSet := make(map[string]bool, len(selfG.NodeIDs))
			for _, mid := range selfG.NodeIDs {
				memberSet[mid] = true
			}
			if memberSet[detourID] {
				return fmt.Errorf("策略分组前置中转不能指向组内自身成员节点，会形成循环代理")
			}
			// Check each member's 3-hop chain: member -> member.DetourID -> group.DetourID.
			for _, mid := range selfG.NodeIDs {
				if m := nodeMap[mid]; m != nil {
					// Ensure neither detourID nor its descendants loop back to this member.
					visNodes[mid] = true
					err := walkTarget(detourID, 1)
					delete(visNodes, mid)
					if err != nil {
						return err
					}
					if mDetour := strings.TrimSpace(m.DetourID); mDetour != "" {
						// Combined chain depth = len(member detour chain) + len(group detour chain).
						if mDetour == detourID {
							return fmt.Errorf("组内成员 %q 的前置中转与策略组前置相同，会形成重复回环", m.DisplayName())
						}
						visNodes[mid] = true
						err = walkTarget(mDetour, 2)
						delete(visNodes, mid)
						if err != nil {
							return err
						}
					}
				}
			}
		}
	}

	return walkTarget(detourID, 1)
}

// ValidateDetourTarget checks whether assigning detourID as the chained relay for nodeID
// is well-formed, supported, and free of node/group cycles.
func ValidateDetourTarget(nodeID, detourID string, nodes []*config.Node, groups []storage.Group) error {
	return validateDetourGraph("node", nodeID, detourID, nodes, groups)
}

// ValidateGroupDetourTarget checks whether assigning detourID as the chained relay for groupID
// is well-formed, supported, and free of node/group cycles (including 3-hop combinations).
func ValidateGroupDetourTarget(groupID, detourID string, nodes []*config.Node, groups []storage.Group) error {
	return validateDetourGraph("group", groupID, detourID, nodes, groups)
}

// ValidateAllDetours validates every configured node and group detour across the full graph.
func ValidateAllDetours(nodes []*config.Node, groups []storage.Group) error {
	for _, n := range nodes {
		if n == nil || strings.TrimSpace(n.DetourID) == "" {
			continue
		}
		if err := ValidateDetourTarget(n.ID, n.DetourID, nodes, groups); err != nil {
			return err
		}
	}
	for _, g := range groups {
		if strings.TrimSpace(g.DetourID) == "" {
			continue
		}
		if err := ValidateGroupDetourTarget(g.ID, g.DetourID, nodes, groups); err != nil {
			return err
		}
	}
	return nil
}

// Compile builds a complete sing-box 1.14+ configuration document.
func Compile(in CompileInput) (*CompileOutput, error) {
	routing := in.Routing
	routing.Normalize()
	in.Routing = routing
	if in.MixedPort <= 0 {
		in.MixedPort = 10808
	}
	if in.ClashAPIPort <= 0 {
		in.ClashAPIPort = 9090
	}
	if in.TUNStack == "" {
		if runtime.GOOS == "linux" {
			in.TUNStack = "mixed"
		} else {
			in.TUNStack = "gvisor"
		}
	}

	out := &CompileOutput{
		IncludedTags: map[string]bool{
			"direct":         true,
			BlockOutboundTag: true,
		},
	}

	nodeMap := make(map[string]*config.Node, len(in.Nodes))
	for _, n := range in.Nodes {
		if n != nil && n.ID != "" {
			nodeMap[n.ID] = n
		}
	}

	// Determine which nodes/endpoints can safely be materialized in sing-box.
	endpoints := []map[string]any{}
	outbounds := []map[string]any{
		buildDirectOutbound(in.ProtectPath),
		{
			"type": "block",
			"tag":  BlockOutboundTag,
		},
	}

	var selectableTags []string
	for _, n := range in.Nodes {
		if n == nil || n.ID == "" {
			continue
		}
		if n.Protocol == config.ProtocolNaive && !in.IncludeNaive {
			out.SkippedNaive = append(out.SkippedNaive, n.ID)
			continue
		}
		tag := NodeTag(n.ID)
		if n.RequiresXray() {
			bridgePort := in.XrayBridgePorts[n.ID]
			if bridgePort <= 0 {
				return nil, fmt.Errorf("missing Xray coprocessor loopback port for node %q", n.ID)
			}
			outbounds = append(outbounds, map[string]any{
				"type":        "socks",
				"tag":         tag,
				"server":      "127.0.0.1",
				"server_port": bridgePort,
				"version":     "5",
			})
			out.IncludedTags[tag] = true
			selectableTags = append(selectableTags, tag)
			continue
		}

		if n.Protocol == config.ProtocolWireGuard {
			ep, err := compileWireGuardEndpoint(n, tag, in.ProtectPath)
			if err != nil {
				return nil, err
			}
			endpoints = append(endpoints, ep)
			out.IncludedTags[tag] = true
			selectableTags = append(selectableTags, tag)
			continue
		}

		ob, err := compileOutbound(n, tag, in.ProtectPath)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, ob)
		out.IncludedTags[tag] = true
		selectableTags = append(selectableTags, tag)
	}

	// Build configured user proxy groups before top-level "proxy" selector.
	groupMap := make(map[string]storage.Group, len(in.Groups))
	for _, g := range in.Groups {
		if g.ID != "" {
			groupMap[g.ID] = g
		}
	}
	buildGroupOutbound := func(g storage.Group, tag string, members []string, defaultMemberTag string) map[string]any {
		strategy := storage.CanonicalGroupStrategy(g.Strategy)
		switch strategy {
		case "urltest":
			interval, idleTimeout, tol := normalizeGroupTiming(g.Interval, "5m", g.ToleranceMS, 50)
			ob := map[string]any{
				"type":      "urltest",
				"tag":       tag,
				"outbounds": members,
				"url":       "https://www.gstatic.com/generate_204",
				"interval":  interval,
				"tolerance": tol,
			}
			if idleTimeout != "" {
				ob["idle_timeout"] = idleTimeout
			}
			return ob
		case "failover":
			interval, idleTimeout, tol := normalizeGroupTiming(g.Interval, "1m", g.ToleranceMS, 1000)
			ob := map[string]any{
				"type":      "urltest",
				"tag":       tag,
				"outbounds": members,
				"url":       "https://www.gstatic.com/generate_204",
				"interval":  interval,
				"tolerance": tol,
			}
			if idleTimeout != "" {
				ob["idle_timeout"] = idleTimeout
			}
			return ob
		case "loadbalance":
			interval, idleTimeout, tol := normalizeGroupTiming(g.Interval, "10m", g.ToleranceMS, 150)
			ob := map[string]any{
				"type":      "urltest",
				"tag":       tag,
				"outbounds": members,
				"url":       "https://www.gstatic.com/generate_204",
				"interval":  interval,
				"tolerance": tol,
			}
			if idleTimeout != "" {
				ob["idle_timeout"] = idleTimeout
			}
			return ob
		default:
			sel := map[string]any{
				"type":                        "selector",
				"tag":                         tag,
				"outbounds":                   members,
				"interrupt_exist_connections": true,
			}
			if defaultMemberTag != "" {
				sel["default"] = defaultMemberTag
			}
			return sel
		}
	}

	groupTagMap := map[string]bool{}
	groupObByID := map[string]map[string]any{}
	groupAutoObByID := map[string]map[string]any{}
	lbShards := map[string][]string{}
	for _, g := range in.Groups {
		members := make([]string, 0, len(g.NodeIDs))
		for _, id := range g.NodeIDs {
			tag := NodeTag(id)
			if out.IncludedTags[tag] {
				members = append(members, tag)
			}
		}
		if len(members) == 0 {
			continue
		}
		gtag := GroupTag(g.ID)
		defTag := ""
		if g.SelectedNodeID != "" && out.IncludedTags[NodeTag(g.SelectedNodeID)] {
			defTag = NodeTag(g.SelectedNodeID)
		}
		strat := storage.CanonicalGroupStrategy(g.Strategy)
		if strat == "urltest" || strat == "failover" {
			// Two-layer hybrid outbound:
			// 1. Internal urltest/failover auto-selector ("group-<id>-auto")
			// 2. Public selector wrapper ("group-<id>") so manual pinning via Clash API works
			//    without restarting TUN and can auto-revert cleanly back to "group-<id>-auto".
			autoTag := GroupAutoTag(g.ID)
			autoOb := buildGroupOutbound(g, autoTag, members, "")
			outbounds = append(outbounds, autoOb)
			groupAutoObByID[g.ID] = autoOb
			out.IncludedTags[autoTag] = true

			selMembers := make([]string, 0, len(members)+1)
			selMembers = append(selMembers, autoTag)
			selMembers = append(selMembers, members...)
			selDef := autoTag
			if g.ManualPin && defTag != "" {
				for _, m := range members {
					if m == defTag {
						selDef = defTag
						break
					}
				}
			}
			selOb := map[string]any{
				"type":                        "selector",
				"tag":                         gtag,
				"outbounds":                   selMembers,
				"default":                     selDef,
				"interrupt_exist_connections": true,
			}
			outbounds = append(outbounds, selOb)
			groupObByID[g.ID] = selOb
			out.IncludedTags[gtag] = true
			groupTagMap[gtag] = true
			continue
		}

		gob := buildGroupOutbound(g, gtag, members, defTag)
		outbounds = append(outbounds, gob)
		groupObByID[g.ID] = gob
		out.IncludedTags[gtag] = true
		groupTagMap[gtag] = true

		if strat == "loadbalance" {
			var healthy []string
			for _, id := range g.NodeIDs {
				tag := NodeTag(id)
				if !out.IncludedTags[tag] {
					continue
				}
				if n := nodeMap[id]; n != nil && n.Latency >= 0 {
					healthy = append(healthy, tag)
				}
			}
			if len(healthy) == 0 {
				healthy = append(healthy, members...)
			}
			if len(healthy) > MaxLoadBalanceShards {
				healthy = healthy[:MaxLoadBalanceShards]
			}
			if len(healthy) > 1 {
				lbShards[gtag] = healthy
			}
		}
	}

	// Wire standalone chained proxy detour references on sing-box native outbounds & WireGuard endpoints.
	obByTag := make(map[string]map[string]any, len(outbounds)+len(endpoints))
	for _, ob := range outbounds {
		if t, ok := ob["tag"].(string); ok && t != "" {
			obByTag[t] = ob
		}
	}
	for _, ep := range endpoints {
		if t, ok := ep["tag"].(string); ok && t != "" {
			obByTag[t] = ep
		}
	}
	resolveRelayTag := func(detourID string) string {
		if gtag := GroupTag(detourID); out.IncludedTags[gtag] {
			return gtag
		}
		if ntag := NodeTag(detourID); out.IncludedTags[ntag] {
			return ntag
		}
		return ""
	}
	for _, n := range in.Nodes {
		if n == nil || n.ID == "" || n.RequiresXray() {
			continue
		}
		detourID := strings.TrimSpace(n.DetourID)
		if detourID == "" {
			continue
		}
		if err := ValidateDetourTarget(n.ID, detourID, in.Nodes, in.Groups); err != nil {
			continue
		}
		relayTag := resolveRelayTag(detourID)
		if relayTag == "" {
			continue
		}
		if ob := obByTag[NodeTag(n.ID)]; ob != nil {
			ob["detour"] = relayTag
			// sing-box forbids combining detour with direct socket dialer options such as protect_path.
			delete(ob, "protect_path")
		}
	}

	// Synthesize scoped chained clones for policy groups that define Group.DetourID.
	// Supports 2-hop (G.Detour -> Member) and 3-hop (G.Detour -> Member.Detour -> Member)
	// without mutating standalone node outbounds.
	scopedCache := map[string]string{}
	var ensureScopedTarget func(targetID, scope, terminalDetourTag string, depth int) string
	ensureScopedTarget = func(targetID, scope, terminalDetourTag string, depth int) string {
		targetID = strings.TrimSpace(targetID)
		if targetID == "" || depth > maxDetourChainDepth {
			return ""
		}
		cacheKey := targetID + "|" + scope + "|" + terminalDetourTag
		if existing, ok := scopedCache[cacheKey]; ok {
			return existing
		}

		// Case 1: targetID is a policy group used as an intermediate hop inside a group detour chain.
		if subG, isGroup := groupMap[targetID]; isGroup {
			scopedGroupTag := GroupTag(subG.ID) + scope
			// Guard recursion before expanding members.
			scopedCache[cacheKey] = scopedGroupTag
			effTerminal := terminalDetourTag
			if subDetour := strings.TrimSpace(subG.DetourID); subDetour != "" {
				if chained := ensureScopedTarget(subDetour, scope, terminalDetourTag, depth+1); chained != "" {
					effTerminal = chained
				}
			}
			var scopedMembers []string
			var scopedDefault string
			for _, mid := range subG.NodeIDs {
				if mtag := ensureScopedTarget(mid, scope, effTerminal, depth+1); mtag != "" {
					scopedMembers = append(scopedMembers, mtag)
					if subG.SelectedNodeID == mid {
						scopedDefault = mtag
					}
				}
			}
			if len(scopedMembers) == 0 {
				delete(scopedCache, cacheKey)
				return ""
			}
			subOb := buildGroupOutbound(subG, scopedGroupTag, scopedMembers, scopedDefault)
			outbounds = append(outbounds, subOb)
			out.IncludedTags[scopedGroupTag] = true
			return scopedGroupTag
		}

		// Case 2: targetID is a node.
		n := nodeMap[targetID]
		if n == nil || !out.IncludedTags[NodeTag(n.ID)] {
			return ""
		}
		if n.RequiresXray() {
			// Xray sidecar SOCKS bridge cannot chain via sing-box detour; leave uncloned.
			return NodeTag(n.ID)
		}
		scopedTag := NodeTag(n.ID) + scope
		scopedCache[cacheKey] = scopedTag

		detourForClone := terminalDetourTag
		if nDetour := strings.TrimSpace(n.DetourID); nDetour != "" {
			if chained := ensureScopedTarget(nDetour, scope, terminalDetourTag, depth+1); chained != "" {
				detourForClone = chained
			}
		}

		if n.Protocol == config.ProtocolWireGuard {
			ep, err := compileWireGuardEndpoint(n, scopedTag, "")
			if err != nil {
				delete(scopedCache, cacheKey)
				return NodeTag(n.ID)
			}
			ep["detour"] = detourForClone
			delete(ep, "protect_path")
			endpoints = append(endpoints, ep)
			out.IncludedTags[scopedTag] = true
			return scopedTag
		}

		ob, err := compileOutbound(n, scopedTag, "")
		if err != nil {
			delete(scopedCache, cacheKey)
			return NodeTag(n.ID)
		}
		ob["detour"] = detourForClone
		delete(ob, "protect_path")
		outbounds = append(outbounds, ob)
		out.IncludedTags[scopedTag] = true
		return scopedTag
	}

	for _, g := range in.Groups {
		gDetour := strings.TrimSpace(g.DetourID)
		if gDetour == "" {
			continue
		}
		gob := groupObByID[g.ID]
		if gob == nil {
			continue
		}
		if err := ValidateGroupDetourTarget(g.ID, gDetour, in.Nodes, in.Groups); err != nil {
			continue
		}
		relayTag := resolveRelayTag(gDetour)
		if relayTag == "" {
			continue
		}
		scope := "--via-" + g.ID
		var scopedMembers []string
		scopedByMemberID := map[string]string{}
		for _, mid := range g.NodeIDs {
			if mtag := ensureScopedTarget(mid, scope, relayTag, 1); mtag != "" {
				scopedMembers = append(scopedMembers, mtag)
				scopedByMemberID[mid] = mtag
			}
		}
		if len(scopedMembers) == 0 {
			continue
		}
		if autoOb := groupAutoObByID[g.ID]; autoOb != nil {
			autoTag := GroupAutoTag(g.ID)
			autoOb["outbounds"] = scopedMembers
			selMembers := make([]string, 0, len(scopedMembers)+1)
			selMembers = append(selMembers, autoTag)
			selMembers = append(selMembers, scopedMembers...)
			gob["outbounds"] = selMembers
			if g.ManualPin && g.SelectedNodeID != "" {
				if defScoped := scopedByMemberID[g.SelectedNodeID]; defScoped != "" {
					gob["default"] = defScoped
				} else {
					gob["default"] = autoTag
				}
			} else {
				gob["default"] = autoTag
			}
		} else {
			gob["outbounds"] = scopedMembers
			if g.SelectedNodeID != "" {
				if defScoped := scopedByMemberID[g.SelectedNodeID]; defScoped != "" {
					gob["default"] = defScoped
				}
			}
		}
		gtag := GroupTag(g.ID)
		if shards, ok := lbShards[gtag]; ok {
			remapped := make([]string, 0, len(shards))
			for _, id := range g.NodeIDs {
				if st := scopedByMemberID[id]; st != "" {
					if n := nodeMap[id]; n != nil && n.Latency >= 0 {
						remapped = append(remapped, st)
					}
				}
			}
			if len(remapped) == 0 {
				remapped = append(remapped, scopedMembers...)
			}
			if len(remapped) > MaxLoadBalanceShards {
				remapped = remapped[:MaxLoadBalanceShards]
			}
			if len(remapped) > 1 {
				lbShards[gtag] = remapped
			}
		}
	}

	// Determine top-level "proxy" selector members and default.
	var proxyMembers []string
	for gtag := range groupTagMap {
		proxyMembers = append(proxyMembers, gtag)
	}
	for _, g := range in.Groups {
		gtag := GroupTag(g.ID)
		if !groupTagMap[gtag] {
			continue
		}
		// Ensure deterministic ordering matching g order (rebuild cleanly).
		_ = gtag
	}
	proxyMembers = proxyMembers[:0]
	for _, g := range in.Groups {
		gtag := GroupTag(g.ID)
		if groupTagMap[gtag] {
			proxyMembers = append(proxyMembers, gtag)
		}
	}
	proxyMembers = append(proxyMembers, selectableTags...)
	hasProxyTargets := len(proxyMembers) > 0
	if routing.KillSwitchEnabled() {
		proxyMembers = append(proxyMembers, BlockOutboundTag)
	} else if !hasProxyTargets {
		proxyMembers = []string{"direct", BlockOutboundTag}
	} else {
		proxyMembers = append(proxyMembers, BlockOutboundTag, "direct")
	}

	defaultProxy := proxyMembers[0]
	if in.ActiveGroupID != "" && out.IncludedTags[GroupTag(in.ActiveGroupID)] {
		defaultProxy = GroupTag(in.ActiveGroupID)
	} else if in.ActiveNodeID != "" && out.IncludedTags[NodeTag(in.ActiveNodeID)] {
		defaultProxy = NodeTag(in.ActiveNodeID)
	} else if !hasProxyTargets && routing.KillSwitchEnabled() {
		defaultProxy = BlockOutboundTag
	}
	out.ActiveTag = defaultProxy

	outbounds = append(outbounds, map[string]any{
		"type":                        "selector",
		"tag":                         "proxy",
		"outbounds":                   proxyMembers,
		"default":                     defaultProxy,
		"interrupt_exist_connections": true,
	})
	out.IncludedTags["proxy"] = true

	// Build listener-specific selectors when ListenConfig binds TargetOutbound, TargetGroupID, or NodeIDs.
	listenerTargets := map[string]string{}
	for _, l := range in.Listeners {
		if l == nil || !l.Enabled || l.Port < 1 || l.Port > 65535 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(l.TargetOutbound), "direct") {
			listenerTargets[l.ID] = "direct"
			continue
		}
		if l.TargetGroupID != "" && out.IncludedTags[GroupTag(l.TargetGroupID)] {
			listenerTargets[l.ID] = GroupTag(l.TargetGroupID)
			continue
		}
		var valid []string
		for _, id := range l.NodeIDs {
			if out.IncludedTags[NodeTag(id)] {
				valid = append(valid, NodeTag(id))
			}
		}
		if len(valid) == 1 {
			listenerTargets[l.ID] = valid[0]
		} else if len(valid) > 1 {
			ltag := "listener-" + l.ID
			outbounds = append(outbounds, map[string]any{
				"type":      "urltest",
				"tag":       ltag,
				"outbounds": valid,
				"url":       "https://www.gstatic.com/generate_204",
				"interval":  "5m",
				"tolerance": 100,
			})
			listenerTargets[l.ID] = ltag
			out.IncludedTags[ltag] = true
		} else {
			listenerTargets[l.ID] = "proxy"
		}
	}

	nameToTag := map[string]string{}
	for _, n := range in.Nodes {
		if n == nil || n.ID == "" {
			continue
		}
		tag := NodeTag(n.ID)
		if !out.IncludedTags[tag] {
			continue
		}
		if key := strings.ToLower(strings.TrimSpace(n.Name)); key != "" {
			nameToTag[key] = tag
		}
		if key := strings.ToLower(strings.TrimSpace(n.DisplayName())); key != "" {
			nameToTag[key] = tag
		}
	}
	for _, g := range in.Groups {
		gtag := GroupTag(g.ID)
		if !out.IncludedTags[gtag] {
			continue
		}
		if key := strings.ToLower(strings.TrimSpace(g.Name)); key != "" {
			nameToTag[key] = gtag
		}
	}

	inbounds := buildInbounds(in)
	compiledRuleSets := buildRuleSets(in.RuleSets, in.ForceRemoteRules)
	ruleSetTags := map[string]bool{}
	for _, rs := range compiledRuleSets {
		if tag, _ := rs["tag"].(string); tag != "" {
			ruleSetTags[tag] = true
		}
	}

	dnsObj := buildDNS(routing, in.Nodes, ruleSetTags, in.ProtectPath)
	routeObj := buildRoute(routing, in, in.Listeners, listenerTargets, compiledRuleSets, ruleSetTags, out.IncludedTags, nameToTag, lbShards, out.ActiveTag)

	clashMode := "Rule"
	switch routing.Mode {
	case "global":
		clashMode = "Global"
	case "direct":
		clashMode = "Direct"
	}

	expObj := map[string]any{
		"clash_api": map[string]any{
			"external_controller":                  fmt.Sprintf("127.0.0.1:%d", in.ClashAPIPort),
			"secret":                               in.ClashAPISecret,
			"default_mode":                         clashMode,
			"access_control_allow_private_network": true,
		},
	}
	if routing.FakeIP && routing.Mode != "direct" {
		cacheCfg := map[string]any{
			"enabled":      true,
			"store_fakeip": true,
		}
		if cp := strings.TrimSpace(in.CacheFilePath); cp != "" {
			cacheCfg["path"] = cp
		}
		expObj["cache_file"] = cacheCfg
	}

	doc := map[string]any{
		"log": map[string]any{
			"level":     routing.LogLevel,
			"timestamp": true,
		},
		"dns":          dnsObj,
		"inbounds":     inbounds,
		"outbounds":    outbounds,
		"route":        routeObj,
		"experimental": expObj,
	}
	if len(endpoints) > 0 {
		doc["endpoints"] = endpoints
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	out.Raw = raw
	return out, nil
}

func buildDirectOutbound(protectPath string) map[string]any {
	d := map[string]any{
		"type": "direct",
		"tag":  "direct",
	}
	if protectPath != "" {
		d["protect_path"] = protectPath
	}
	return d
}

func buildInbounds(in CompileInput) []map[string]any {
	var inbounds []map[string]any
	if in.EnableTUN && !in.AndroidMode {
		tunAddresses := []string{"172.19.0.1/30"}
		tunExclude := []string{"127.0.0.0/8"}
		if in.Routing.BypassLAN && in.Routing.AllowLANBroadcast {
			// On Desktop TUN, exclude only non-DNS link-local, multicast (mDNS/SSDP/DLNA), and
			// broadcast (255.255.255.255 for KDE Connect) ranges at the OS/nftables route layer.
			// Do NOT exclude private unicast ranges (10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12,
			// 192.168.0.0/16): Desktop hosts commonly send OS DNS queries to router/Tailscale
			// resolvers (192.168.x.1, 10.x.x.1, 100.100.100.100:53), which must enter TUN for
			// hijack-dns; non-DNS LAN unicast still routes directly via ip_is_private -> direct.
			tunExclude = append(tunExclude,
				"169.254.0.0/16",
				"224.0.0.0/4",
				"240.0.0.0/4",
			)
		}
		if in.Routing.IPv6Enabled() {
			tunAddresses = append(tunAddresses, "fdfe:dcba:9876::1/126")
			tunExclude = append(tunExclude, "::1/128")
			if in.Routing.BypassLAN && in.Routing.AllowLANBroadcast {
				tunExclude = append(tunExclude, "fe80::/10", "ff00::/8")
			}
		}
		tun := map[string]any{
			"type":                  "tun",
			"tag":                   "tun-in",
			"address":               tunAddresses,
			"mtu":                   1500,
			"auto_route":            true,
			"strict_route":          true,
			"stack":                 in.TUNStack,
			"route_exclude_address": tunExclude,
		}
		// macOS kernel requires utun[0-9]* names; omitting interface_name lets sing-box allocate the next free utunX.
		if runtime.GOOS != "darwin" {
			tun["interface_name"] = "prismray0"
		}
		if runtime.GOOS == "linux" {
			tun["auto_redirect"] = true
			tun["iproute2_table_index"] = 2178
			tun["iproute2_rule_index"] = 7000
			tun["auto_redirect_iproute2_fallback_rule_index"] = 32778
			tun["auto_redirect_input_mark"] = "0x21781"
			tun["auto_redirect_output_mark"] = "0x21782"
			tun["auto_redirect_reset_mark"] = "0x21783"
			tun["auto_redirect_nfqueue"] = 2178
		}
		inbounds = append(inbounds, tun)
	}

	usedPorts := map[int]bool{}
	for _, l := range in.Listeners {
		if l == nil || !l.Enabled || l.Port < 1 || l.Port > 65535 {
			continue
		}
		usedPorts[l.Port] = true
		listenAddr := l.Address
		if l.AllowLAN {
			listenAddr = "0.0.0.0"
		} else if listenAddr == "" {
			listenAddr = "127.0.0.1"
		}
		proto := l.Protocol
		if proto != "socks" && proto != "http" {
			proto = "mixed"
		}
		entry := map[string]any{
			"type":        proto,
			"tag":         "in-" + l.ID,
			"listen":      listenAddr,
			"listen_port": l.Port,
		}
		if l.Username != "" || l.Password != "" {
			entry["users"] = []map[string]string{
				{"username": l.Username, "password": l.Password},
			}
		}
		inbounds = append(inbounds, entry)
	}

	if !usedPorts[in.MixedPort] {
		inbounds = append(inbounds, map[string]any{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": in.MixedPort,
		})
	}

	if in.AndroidMode && in.AndroidAppSocksPort > 0 && strings.TrimSpace(in.AndroidAppSocksSecret) != "" && len(in.AndroidAppPackages) > 0 {
		seen := map[string]bool{AndroidAppOtherUser: true}
		users := []map[string]string{
			{"username": AndroidAppOtherUser, "password": in.AndroidAppSocksSecret},
		}
		for _, rawPkg := range in.AndroidAppPackages {
			pkg := strings.TrimSpace(rawPkg)
			if pkg == "" || seen[pkg] {
				continue
			}
			seen[pkg] = true
			users = append(users, map[string]string{"username": pkg, "password": in.AndroidAppSocksSecret})
		}
		inbounds = append(inbounds, map[string]any{
			"type":        "socks",
			"tag":         AndroidAppInboundTag,
			"listen":      "127.0.0.1",
			"listen_port": in.AndroidAppSocksPort,
			"users":       users,
		})
	}
	return inbounds
}

func buildRuleSets(specs []ruleset.RuleSetSpec, forceRemote bool) []map[string]any {
	var out []map[string]any
	for _, s := range specs {
		if !s.Enabled || s.Tag == "" {
			continue
		}
		if s.LocalPath != "" {
			if st, err := os.Stat(s.LocalPath); err == nil && !st.IsDir() && st.Size() > 0 {
				out = append(out, map[string]any{
					"tag":    s.Tag,
					"type":   "local",
					"format": "binary",
					"path":   s.LocalPath,
				})
				continue
			}
		}
		if forceRemote && s.URL != "" {
			out = append(out, map[string]any{
				"tag":             s.Tag,
				"type":            "remote",
				"format":          "binary",
				"url":             s.URL,
				"update_interval": "24h",
			})
			continue
		}
		// Do not synthesize misleading tiny inline rule sets when real .srs files are not loaded yet;
		// BlockAds and BypassCN stay inactive until real local .srs rule sets are synced.
	}
	return out
}

var dohBootstrapHosts = map[string][]string{
	"dns.google":         {"8.8.8.8", "8.8.4.4"},
	"cloudflare-dns.com": {"1.1.1.1", "1.0.0.1"},
	"one.one.one.one":    {"1.1.1.1", "1.0.0.1"},
	"dns.quad9.net":      {"9.9.9.9", "149.112.112.112"},
	"dns.alidns.com":     {"223.5.5.5", "223.6.6.6"},
	"doh.pub":            {"1.12.12.12", "120.53.53.53"},
}

func isLiteralIPHost(host string) bool {
	_, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(host), "[]"))
	return err == nil
}

func parseDNSServer(tag, addr string, directServer bool, protectPath string) (map[string]any, string) {
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, "https://") {
		if u, err := url.Parse(addr); err == nil && u.Hostname() != "" {
			port := 443
			if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
				port = p
			}
			path := u.EscapedPath()
			if path == "" {
				path = "/dns-query"
			}
			host := strings.ToLower(u.Hostname())
			srv := map[string]any{
				"tag":         tag,
				"type":        "https",
				"server":      host,
				"server_port": port,
				"path":        path,
			}
			bootstrapHost := ""
			if !directServer {
				srv["detour"] = "proxy"
				if !isLiteralIPHost(host) {
					if _, ok := dohBootstrapHosts[host]; ok {
						srv["domain_resolver"] = "doh-bootstrap-dns"
						bootstrapHost = host
					} else {
						srv["domain_resolver"] = "local-dns"
					}
				}
			} else if protectPath != "" {
				srv["protect_path"] = protectPath
			}
			return srv, bootstrapHost
		}
	}
	if strings.HasPrefix(addr, "tls://") {
		host := strings.ToLower(strings.TrimPrefix(addr, "tls://"))
		srv := map[string]any{
			"tag":    tag,
			"type":   "tls",
			"server": host,
		}
		bootstrapHost := ""
		if !directServer {
			srv["detour"] = "proxy"
			if !isLiteralIPHost(host) {
				if _, ok := dohBootstrapHosts[host]; ok {
					srv["domain_resolver"] = "doh-bootstrap-dns"
					bootstrapHost = host
				} else {
					srv["domain_resolver"] = "local-dns"
				}
			}
		} else if protectPath != "" {
			srv["protect_path"] = protectPath
		}
		return srv, bootstrapHost
	}
	host := addr
	if strings.HasPrefix(host, "udp://") {
		host = strings.TrimPrefix(host, "udp://")
	}
	if host == "" {
		host = "223.5.5.5"
	}
	srv := map[string]any{
		"tag":    tag,
		"type":   "udp",
		"server": host,
	}
	if !directServer {
		srv["detour"] = "proxy"
	} else if protectPath != "" {
		srv["protect_path"] = protectPath
	}
	return srv, ""
}

func collectFakeIPBypass(routing ruleset.RoutingProfile, nodes []*config.Node) (exactDomains, domainSuffixes []string) {
	exactSet := map[string]bool{
		"localhost": true,
	}
	suffixSet := map[string]bool{
		".lan":                true,
		".local":              true,
		".arpa":               true,
		".home.arpa":          true,
		".ts.net":             true,
		"pool.ntp.org":        true,
		"time.apple.com":      true,
		"time.windows.com":    true,
		"msftconnecttest.com": true,
		"msftncsi.com":        true,
	}
	for _, n := range nodes {
		if n == nil {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n.Address)), ".")
		if host == "" {
			continue
		}
		if _, err := netip.ParseAddr(host); err != nil {
			exactSet[host] = true
		}
	}
	for _, cr := range routing.CustomRules {
		if !cr.Enabled || cr.Outbound != "direct" {
			continue
		}
		for _, d := range cr.Domains {
			if clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), "."); clean != "" {
				exactSet[clean] = true
			}
		}
		for _, s := range cr.DomainSuffix {
			if clean := strings.ToLower(strings.TrimSpace(s)); clean != "" {
				suffixSet[clean] = true
			}
		}
	}
	for _, f := range routing.FakeIPFilter {
		clean := strings.ToLower(strings.TrimSpace(f))
		clean = strings.TrimPrefix(clean, "*.")
		clean = strings.TrimPrefix(clean, "+.")
		if clean != "" {
			suffixSet[clean] = true
		}
	}
	for d := range exactSet {
		exactDomains = append(exactDomains, d)
	}
	for s := range suffixSet {
		domainSuffixes = append(domainSuffixes, s)
	}
	sort.Strings(exactDomains)
	sort.Strings(domainSuffixes)
	return exactDomains, domainSuffixes
}

func buildDNS(routing ruleset.RoutingProfile, nodes []*config.Node, ruleSetTags map[string]bool, protectPath string) map[string]any {
	localSrv, _ := parseDNSServer("local-dns", routing.LocalDNS, true, protectPath)
	servers := []map[string]any{localSrv}
	finalDNS := "local-dns"

	var rules []map[string]any
	if routing.Mode != "direct" {
		remoteSrv, bootstrapHost := parseDNSServer("remote-dns", routing.RemoteDNS, false, "")
		if bootstrapHost != "" {
			if ips, ok := dohBootstrapHosts[bootstrapHost]; ok {
				servers = append(servers, map[string]any{
					"tag":        "doh-bootstrap-dns",
					"type":       "hosts",
					"predefined": map[string][]string{bootstrapHost: ips},
				})
			}
		}
		servers = append(servers, remoteSrv)
		finalDNS = "remote-dns"
		rules = append(rules, map[string]any{"clash_mode": "Direct", "server": "local-dns"})
		if routing.WebRTCMode == "block" {
			rules = append(rules, map[string]any{
				"domain_keyword": []string{"stun."},
				"action":         "predefined",
				"rcode":          "NOERROR",
			})
		}

		ipv6Enabled := routing.IPv6Enabled()
		if routing.FakeIP {
			fakeSrv := map[string]any{
				"tag":         "fakeip-dns",
				"type":        "fakeip",
				"inet4_range": routing.FakeIPv4Range,
			}
			if ipv6Enabled {
				fakeSrv["inet6_range"] = routing.FakeIPv6Range
			}
			servers = append(servers, fakeSrv)
			exactDomains, domainSuffixes := collectFakeIPBypass(routing, nodes)
			if len(exactDomains) > 0 {
				rules = append(rules, map[string]any{"domain": exactDomains, "server": "local-dns"})
			}
			if len(domainSuffixes) > 0 {
				rules = append(rules, map[string]any{"domain_suffix": domainSuffixes, "server": "local-dns"})
			}
			fakeQueryTypes := []string{"A"}
			if ipv6Enabled {
				fakeQueryTypes = []string{"A", "AAAA"}
			}
			if !ipv6Enabled {
				rules = append(rules, map[string]any{
					"clash_mode": "Global",
					"query_type": []string{"AAAA", "HTTPS"},
					"action":     "predefined",
					"rcode":      "NOERROR",
				})
			}
			rules = append(rules, map[string]any{
				"clash_mode":  "Global",
				"query_type":  fakeQueryTypes,
				"server":      "fakeip-dns",
				"rewrite_ttl": 1,
			})
			if routing.BypassCN && ruleSetTags[ruleset.TagGeoSiteCN] {
				rules = append(rules, map[string]any{"rule_set": ruleset.TagGeoSiteCN, "server": "local-dns"})
			}
			if !ipv6Enabled {
				rules = append(rules, map[string]any{
					"query_type": []string{"AAAA", "HTTPS"},
					"action":     "predefined",
					"rcode":      "NOERROR",
				})
			}
			rules = append(rules, map[string]any{
				"query_type":  fakeQueryTypes,
				"server":      "fakeip-dns",
				"rewrite_ttl": 1,
			})
		} else {
			if !ipv6Enabled {
				rules = append(rules, map[string]any{
					"clash_mode": "Global",
					"query_type": []string{"AAAA", "HTTPS"},
					"action":     "predefined",
					"rcode":      "NOERROR",
				})
			}
			rules = append(rules, map[string]any{"clash_mode": "Global", "server": "remote-dns"})
			if routing.BypassCN && ruleSetTags[ruleset.TagGeoSiteCN] {
				rules = append(rules, map[string]any{"rule_set": ruleset.TagGeoSiteCN, "server": "local-dns"})
			}
			if !ipv6Enabled {
				rules = append(rules, map[string]any{
					"query_type": []string{"AAAA", "HTTPS"},
					"action":     "predefined",
					"rcode":      "NOERROR",
				})
			}
		}
	}

	dnsDoc := map[string]any{
		"servers":  servers,
		"final":    finalDNS,
		"strategy": routing.DomainStrategy,
	}
	if len(rules) > 0 {
		dnsDoc["rules"] = rules
	}
	return dnsDoc
}

func makeIPv4ResolveRule(match map[string]any) map[string]any {
	r := make(map[string]any, len(match)+3)
	for k, v := range match {
		r[k] = v
	}
	r["action"] = "resolve"
	r["server"] = "remote-dns"
	r["strategy"] = "ipv4_only"
	return r
}

const domainHashAlphabet = "scmpatbdflghrnoeuivkwyjqzx0123456789"

// loadBalanceAffinityDomains pins multi-domain ecosystems (Google Play / Auth & IP-check suites)
// to shard 0 under load-balance groups so linked requests never split across different exit IPs.
var loadBalanceAffinityDomains = []string{
	"google.com",
	"googleapis.com",
	"gstatic.com",
	"googleusercontent.com",
	"ggpht.com",
	"gvt1.com",
	"gvt2.com",
	"youtube.com",
	"googlevideo.com",
	"ytimg.com",
	"ippure.com",
}

// googlePlayAllowlistDomains prevents geosite-category-ads-all from blocking Google Play Store,
// Play Points redemption, Play Billing, and Play Integrity telemetry endpoints.
var googlePlayAllowlistDomains = []string{
	"play.google.com",
	"play.googleapis.com",
	"play-fe.googleapis.com",
	"playatoms-pa.googleapis.com",
	"play-lh.googleusercontent.com",
	"android.clients.google.com",
	"payments.google.com",
	"pay.google.com",
	"firebaseinstallations.googleapis.com",
	"firebaselogging-pa.googleapis.com",
}

// BuildDomainHashBucketRegexes splits eTLD+1 root domains deterministically into K shards.
func BuildDomainHashBucketRegexes(shardCount int) []string {
	if shardCount <= 1 {
		return nil
	}
	if shardCount > MaxLoadBalanceShards {
		shardCount = MaxLoadBalanceShards
	}
	buckets := make([]strings.Builder, shardCount)
	for idx := 0; idx < len(domainHashAlphabet); idx++ {
		buckets[idx%shardCount].WriteByte(domainHashAlphabet[idx])
	}
	regexes := make([]string, shardCount)
	for i := 0; i < shardCount; i++ {
		regexes[i] = `(?:^|\.)[` + buckets[i].String() + `][a-z0-9-]*\.(?:(?:co|com|org|net|gov|edu|ac)\.[a-z]{2}|[a-z]{2,10})$`
	}
	return regexes
}

// DomainHashShardIndex returns the deterministic shard index a domain resolves to, or -1 if unsharded.
func DomainHashShardIndex(domain string, shardCount int) int {
	clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if clean == "" || shardCount <= 1 {
		return -1
	}
	regexes := BuildDomainHashBucketRegexes(shardCount)
	for i, pattern := range regexes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(clean) {
			return i
		}
	}
	return -1
}

func cloneRuleMap(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func appendShardedOrDirectRoute(
	rules *[]map[string]any,
	baseCond map[string]any,
	shardGroupTag string,
	fallbackOutbound string,
	lbShards map[string][]string,
	preResolveIPv4 bool,
) {
	shards := lbShards[shardGroupTag]
	if len(shards) > 1 {
		if preResolveIPv4 {
			*rules = append(*rules, makeIPv4ResolveRule(baseCond))
		}
		// Keep Google ecosystem & IP-verification suites pinned to shard 0 so multi-domain
		// sessions (e.g. Google Play Points / Auth / ippure.com) never split across exit IPs.
		if len(baseCond) == 0 {
			*rules = append(*rules, map[string]any{
				"domain_suffix": loadBalanceAffinityDomains,
				"outbound":      shards[0],
			})
		} else if _, hasSuffix := baseCond["domain_suffix"]; !hasSuffix {
			aff := cloneRuleMap(baseCond)
			aff["domain_suffix"] = loadBalanceAffinityDomains
			aff["outbound"] = shards[0]
			*rules = append(*rules, aff)
		}
		for i, rx := range BuildDomainHashBucketRegexes(len(shards)) {
			if len(baseCond) == 0 {
				*rules = append(*rules, map[string]any{
					"domain_regex": []string{rx},
					"outbound":     shards[i],
				})
			} else {
				*rules = append(*rules, map[string]any{
					"type":     "logical",
					"mode":     "and",
					"rules":    []map[string]any{cloneRuleMap(baseCond), {"domain_regex": []string{rx}}},
					"outbound": shards[i],
				})
			}
		}
		if len(baseCond) > 0 && fallbackOutbound != "" {
			fb := cloneRuleMap(baseCond)
			fb["outbound"] = fallbackOutbound
			*rules = append(*rules, fb)
		}
		return
	}

	if preResolveIPv4 && fallbackOutbound != "direct" && fallbackOutbound != BlockOutboundTag {
		*rules = append(*rules, makeIPv4ResolveRule(baseCond))
	}
	if len(baseCond) > 0 && fallbackOutbound != "" {
		r := cloneRuleMap(baseCond)
		r["outbound"] = fallbackOutbound
		*rules = append(*rules, r)
	}
}

func buildRoute(
	routing ruleset.RoutingProfile,
	in CompileInput,
	listeners []*config.ListenConfig,
	listenerTargets map[string]string,
	compiledRuleSets []map[string]any,
	ruleSetTags map[string]bool,
	includedTags map[string]bool,
	nameToTag map[string]string,
	lbShards map[string][]string,
	activeTag string,
) map[string]any {
	// When IPv6 is disabled (prefer_ipv4 / ipv4_only), pre-resolve domain-targeted proxy flows
	// (e.g. Chrome HTTP CONNECT / SOCKS5h via mixed-in) to IPv4 through remote-dns so remote VPS
	// outbounds never stall or reset TLS on broken remote IPv6 / domain filters (e.g. ippure.com).
	// Existing IPv4 destinations from TUN are already IP literals and skip resolution with zero overhead.
	preResolveIPv4 := !routing.IPv6Enabled() && routing.Mode != "direct"
	rules := []map[string]any{
		{"action": "sniff"},
	}
	if routing.HijackDNSEnabled() {
		rules = append(rules,
			map[string]any{"protocol": "dns", "action": "hijack-dns"},
			map[string]any{"port": 53, "action": "hijack-dns"},
		)
	}
	// Dedicated multi-inbound listener bindings take priority over global/direct/general rules
	// so secondary listening ports reliably steer to their bound node, group, or direct exit.
	for _, l := range listeners {
		if l == nil || !l.Enabled {
			continue
		}
		target := listenerTargets[l.ID]
		if target != "" && target != "proxy" {
			appendShardedOrDirectRoute(&rules, map[string]any{
				"inbound": []string{"in-" + l.ID},
			}, target, target, lbShards, preResolveIPv4)
		}
	}
	rules = append(rules, map[string]any{"clash_mode": "Direct", "outbound": "direct"})

	if routing.Mode != "direct" {
		switch routing.WebRTCMode {
		case "block":
			rules = append(rules,
				map[string]any{"protocol": []string{"stun"}, "action": "reject"},
				map[string]any{"network": []string{"udp"}, "port": []int{3478, 5349, 19302, 19305, 19306, 19307}, "action": "reject"},
			)
		case "proxy":
			rules = append(rules,
				map[string]any{"protocol": []string{"stun"}, "outbound": "proxy"},
				map[string]any{"network": []string{"udp"}, "port": []int{3478, 5349, 19302, 19305, 19306, 19307}, "outbound": "proxy"},
			)
		}
	}

	appendShardedOrDirectRoute(&rules, map[string]any{"clash_mode": "Global"}, activeTag, "proxy", lbShards, preResolveIPv4)

	if routing.BypassLAN {
		if routing.FakeIP {
			// Avoid sing-box ip_is_private matching FakeIPv6 fc00::/18 inside fc00::/7.
			rules = append(rules, map[string]any{
				"ip_cidr":  []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "::1/128", "fe80::/10", "fd00::/8"},
				"outbound": "direct",
			})
		} else {
			rules = append(rules, map[string]any{"ip_is_private": true, "outbound": "direct"})
		}
	}
	if !routing.IPv6Enabled() && routing.Mode != "direct" && (in.AndroidMode || in.EnableTUN) {
		// Reject global IPv6 destinations when IPv6 is disabled so Android/TUN captures ::/0
		// without leaking real ISP IPv6 and apps fall back immediately to proxied IPv4.
		rules = append(rules, map[string]any{
			"ip_cidr": []string{"2000::/3"},
			"action":  "reject",
		})
	}
	if routing.BlockAds && routing.Mode != "direct" && ruleSetTags[ruleset.TagGeoSiteAds] {
		// Exclude Google Play Store / Play Points / Play Billing domains from ad rejection
		// without shadowing downstream user custom rules.
		rules = append(rules, map[string]any{
			"type": "logical",
			"mode": "and",
			"rules": []map[string]any{
				{"rule_set": ruleset.TagGeoSiteAds},
				{"domain_suffix": googlePlayAllowlistDomains, "invert": true},
			},
			"action": "reject",
		})
	}

	for _, cr := range routing.CustomRules {
		if !cr.Enabled {
			continue
		}
		rule := map[string]any{}
		if len(cr.Domains) > 0 {
			rule["domain"] = cr.Domains
		}
		if len(cr.DomainSuffix) > 0 {
			rule["domain_suffix"] = cr.DomainSuffix
		}
		if len(cr.DomainKeyword) > 0 {
			rule["domain_keyword"] = cr.DomainKeyword
		}
		if len(cr.DomainRegex) > 0 {
			rule["domain_regex"] = cr.DomainRegex
		}
		if len(cr.IPCIDR) > 0 {
			rule["ip_cidr"] = cr.IPCIDR
		}
		if len(cr.SourceIPCIDR) > 0 {
			rule["source_ip_cidr"] = cr.SourceIPCIDR
		}
		if cr.IPIsPrivate {
			rule["ip_is_private"] = true
		}
		if len(cr.Network) > 0 {
			rule["network"] = cr.Network
		}
		if len(cr.ProcessName) > 0 {
			rule["process_name"] = cr.ProcessName
		}
		if len(cr.ProcessPath) > 0 {
			rule["process_path"] = cr.ProcessPath
		}
		if len(cr.PackageName) > 0 {
			if in.AndroidMode && in.AndroidAppSocksPort > 0 {
				// On unrooted Android, tun2socks resolves the real UID/package via ConnectivityManager
				// and authenticates into android-app-in using the package name as SOCKS5 auth_user.
				rule["auth_user"] = cr.PackageName
			} else {
				rule["package_name"] = cr.PackageName
			}
		}
		if len(cr.Port) > 0 {
			rule["port"] = cr.Port
		}
		if len(cr.PortRange) > 0 {
			rule["port_range"] = cr.PortRange
		}
		if len(cr.SourcePort) > 0 {
			rule["source_port"] = cr.SourcePort
		}
		if len(cr.Protocol) > 0 {
			rule["protocol"] = cr.Protocol
		}
		if len(cr.Inbound) > 0 {
			rule["inbound"] = cr.Inbound
		}
		var validRS []string
		for _, rsTag := range cr.RuleSet {
			if ruleSetTags[rsTag] {
				validRS = append(validRS, rsTag)
			}
		}
		if len(validRS) > 0 {
			rule["rule_set"] = validRS
		}
		if len(rule) == 0 {
			continue
		}
		if cr.Invert {
			rule["invert"] = true
		}
		if cr.Outbound == "block" || cr.Outbound == "reject" {
			rule["action"] = "reject"
			rules = append(rules, rule)
		} else {
			outTag := cr.Outbound
			if !includedTags[outTag] {
				if includedTags[NodeTag(outTag)] {
					outTag = NodeTag(outTag)
				} else if includedTags[GroupTag(outTag)] {
					outTag = GroupTag(outTag)
				} else if mapped, ok := nameToTag[strings.ToLower(strings.TrimSpace(outTag))]; ok && includedTags[mapped] {
					outTag = mapped
				} else {
					outTag = "proxy"
				}
			}
			shardTarget := outTag
			if outTag == "proxy" {
				shardTarget = activeTag
			}
			appendShardedOrDirectRoute(&rules, rule, shardTarget, outTag, lbShards, preResolveIPv4)
		}
	}

	if routing.Mode == "rule" && routing.BypassCN {
		var cnSets []string
		if ruleSetTags[ruleset.TagGeoSiteCN] {
			cnSets = append(cnSets, ruleset.TagGeoSiteCN)
		}
		if ruleSetTags[ruleset.TagGeoIPCN] {
			cnSets = append(cnSets, ruleset.TagGeoIPCN)
		}
		if len(cnSets) > 0 {
			rules = append(rules, map[string]any{
				"rule_set": cnSets,
				"outbound": "direct",
			})
		}
	}

	finalOutbound := "proxy"
	if routing.Mode == "direct" {
		finalOutbound = "direct"
	} else {
		// Pre-resolve remaining proxy domains to IPv4 via remote-dns so mixed/SOCKS5
		// CONNECT domains (e.g. ippure.com) do not trigger broken remote VPS AAAA dials.
		if preResolveIPv4 {
			rules = append(rules, makeIPv4ResolveRule(nil))
		}
		if len(lbShards[activeTag]) > 1 {
			appendShardedOrDirectRoute(&rules, nil, activeTag, "", lbShards, false)
		}
	}

	routeDoc := map[string]any{
		"rules":                   rules,
		"final":                   finalOutbound,
		"default_domain_resolver": "local-dns",
	}
	if !in.AndroidMode {
		routeDoc["auto_detect_interface"] = true
	}
	// Do NOT set override_android_vpn on non-root Android VpnService: sing-box would
	// pick the VPN's own tun0 routing table as its default outbound interface and loop!
	if in.DefaultMark != 0 && !(in.EnableTUN && !in.AndroidMode && runtime.GOOS == "linux") {
		routeDoc["default_mark"] = fmt.Sprintf("0x%x", in.DefaultMark)
	}
	if len(compiledRuleSets) > 0 {
		routeDoc["rule_set"] = compiledRuleSets
	}
	return routeDoc
}

func compileWireGuardEndpoint(n *config.Node, tag, protectPath string) (map[string]any, error) {
	pk := n.PeerPublicKey
	if pk == "" {
		pk = n.PublicKey
	}
	addrs := n.LocalAddresses
	if len(addrs) == 0 {
		addrs = []string{"10.0.0.2/32"}
	}
	mtu := n.MTU
	if mtu <= 0 {
		mtu = 1408
	}
	peer := map[string]any{
		"address":     n.Address,
		"port":        n.Port,
		"public_key":  pk,
		"allowed_ips": []string{"0.0.0.0/0", "::/0"},
	}
	if n.PreSharedKey != "" {
		peer["pre_shared_key"] = n.PreSharedKey
	}
	if len(n.Reserved) == 3 {
		peer["reserved"] = []int{int(n.Reserved[0]), int(n.Reserved[1]), int(n.Reserved[2])}
	}
	ep := map[string]any{
		"type":        "wireguard",
		"tag":         tag,
		"address":     addrs,
		"private_key": n.PrivateKey,
		"mtu":         mtu,
		"peers":       []map[string]any{peer},
	}
	if protectPath != "" {
		ep["protect_path"] = protectPath
	}
	return ep, nil
}

func buildTLSBlock(n *config.Node, forceTLS bool) map[string]any {
	sec := strings.ToLower(strings.TrimSpace(n.Security))
	if !forceTLS && sec != "tls" && sec != "reality" {
		return nil
	}
	tls := map[string]any{
		"enabled": true,
	}
	if n.Sni != "" {
		tls["server_name"] = n.Sni
	} else if n.Address != "" {
		tls["server_name"] = n.Address
	}
	if n.AllowInsecure {
		tls["insecure"] = true
	}
	if len(n.ALPN) > 0 {
		tls["alpn"] = n.ALPN
	}
	fp := n.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	if sec == "reality" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": n.PublicKey,
			"short_id":   n.ShortID,
		}
	} else if n.Protocol != config.ProtocolHysteria2 && n.Protocol != config.ProtocolTUIC {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	return tls
}

func buildTransportBlock(n *config.Node) map[string]any {
	netType := strings.ToLower(strings.TrimSpace(n.Network))
	switch netType {
	case "ws":
		tr := map[string]any{
			"type": "ws",
		}
		if n.Path != "" {
			tr["path"] = n.Path
		}
		if len(n.WSHeaders) > 0 {
			tr["headers"] = n.WSHeaders
		} else if n.Host != "" {
			tr["headers"] = map[string]string{"Host": n.Host}
		}
		if n.EarlyData > 0 {
			tr["max_early_data"] = n.EarlyData
		}
		if n.EarlyDataHeader != "" {
			tr["early_data_header_name"] = n.EarlyDataHeader
		}
		return tr
	case "grpc":
		return map[string]any{
			"type":         "grpc",
			"service_name": n.ServiceName,
		}
	case "http", "h2":
		tr := map[string]any{
			"type": "http",
		}
		if n.Path != "" {
			tr["path"] = n.Path
		}
		if n.Host != "" {
			tr["host"] = []string{n.Host}
		}
		return tr
	case "httpupgrade":
		tr := map[string]any{
			"type": "httpupgrade",
		}
		if n.Path != "" {
			tr["path"] = n.Path
		}
		if n.Host != "" {
			tr["host"] = n.Host
		}
		return tr
	default:
		return nil
	}
}

func compileOutbound(n *config.Node, tag, protectPath string) (map[string]any, error) {
	ob := map[string]any{
		"type":        string(n.Protocol),
		"tag":         tag,
		"server":      n.Address,
		"server_port": n.Port,
	}
	if protectPath != "" {
		ob["protect_path"] = protectPath
	}

	switch n.Protocol {
	case config.ProtocolVLESS:
		ob["uuid"] = n.UUID
		if n.Flow != "" {
			ob["flow"] = n.Flow
		}
		if tls := buildTLSBlock(n, false); tls != nil {
			ob["tls"] = tls
		}
		if tr := buildTransportBlock(n); tr != nil {
			ob["transport"] = tr
		}

	case config.ProtocolVMess:
		ob["uuid"] = n.UUID
		sec := n.Cipher
		if sec == "" {
			sec = "auto"
		}
		ob["security"] = sec
		ob["alter_id"] = n.AlterID
		if tls := buildTLSBlock(n, false); tls != nil {
			ob["tls"] = tls
		}
		if tr := buildTransportBlock(n); tr != nil {
			ob["transport"] = tr
		}

	case config.ProtocolTrojan:
		ob["password"] = n.Password
		if tls := buildTLSBlock(n, true); tls != nil {
			ob["tls"] = tls
		}
		if tr := buildTransportBlock(n); tr != nil {
			ob["transport"] = tr
		}

	case config.ProtocolShadowsocks:
		method := n.Method
		if method == "" {
			method = n.Security
		}
		ob["method"] = method
		ob["password"] = n.Password
		if n.UoT {
			ob["udp_over_tcp"] = true
		}

	case config.ProtocolHysteria2:
		ob["password"] = n.Password
		if n.UpMbps > 0 {
			ob["up_mbps"] = n.UpMbps
		}
		if n.DownMbps > 0 {
			ob["down_mbps"] = n.DownMbps
		}
		if n.ObfsType != "" && n.ObfsPassword != "" {
			ob["obfs"] = map[string]any{
				"type":     n.ObfsType,
				"password": n.ObfsPassword,
			}
		}
		if n.HopPorts != "" {
			ob["server_ports"] = strings.Split(n.HopPorts, ",")
		}
		if n.HopInterval != "" {
			ob["hop_interval"] = n.HopInterval
		}
		if tls := buildTLSBlock(n, true); tls != nil {
			ob["tls"] = tls
		}

	case config.ProtocolTUIC:
		ob["uuid"] = n.UUID
		ob["password"] = n.Password
		if n.CongestionControl != "" {
			ob["congestion_control"] = n.CongestionControl
		}
		if n.UDPRelayMode != "" {
			ob["udp_relay_mode"] = n.UDPRelayMode
		}
		if n.ZeroRTTHandshake {
			ob["zero_rtt_handshake"] = true
		}
		if tls := buildTLSBlock(n, true); tls != nil {
			ob["tls"] = tls
		}

	case config.ProtocolAnyTLS:
		ob["password"] = n.Password
		if n.IdleSessionCheckInterval != "" {
			ob["idle_session_check_interval"] = n.IdleSessionCheckInterval
		}
		if n.IdleSessionTimeout != "" {
			ob["idle_session_timeout"] = n.IdleSessionTimeout
		}
		if n.MinIdleSession > 0 {
			ob["min_idle_session"] = n.MinIdleSession
		}
		if tls := buildTLSBlock(n, true); tls != nil {
			ob["tls"] = tls
		}

	case config.ProtocolNaive:
		if n.Username != "" {
			ob["username"] = n.Username
		}
		if n.Password != "" {
			ob["password"] = n.Password
		}
		if n.NaiveQuic {
			ob["quic"] = true
		}
		if len(n.ExtraHeaders) > 0 {
			ob["extra_headers"] = n.ExtraHeaders
		}
		if tls := buildTLSBlock(n, true); tls != nil {
			ob["tls"] = tls
		}

	case config.ProtocolSocks:
		ob["version"] = "5"
		if n.Username != "" {
			ob["username"] = n.Username
		}
		if n.Password != "" {
			ob["password"] = n.Password
		}

	case config.ProtocolHTTP:
		if n.Username != "" {
			ob["username"] = n.Username
		}
		if n.Password != "" {
			ob["password"] = n.Password
		}
		if tls := buildTLSBlock(n, false); tls != nil {
			ob["tls"] = tls
		}

	default:
		return nil, fmt.Errorf("unsupported outbound protocol %q", n.Protocol)
	}
	return ob, nil
}

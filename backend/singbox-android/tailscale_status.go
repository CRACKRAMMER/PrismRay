// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
)

type tailscalePeerSnapshot struct {
	StableID       string   `json:"stable_id,omitempty"`
	Hostname       string   `json:"hostname"`
	DNSName        string   `json:"dns_name,omitempty"`
	OS             string   `json:"os,omitempty"`
	IPv4           string   `json:"ipv4,omitempty"`
	IPv6           string   `json:"ipv6,omitempty"`
	TailscaleIPs   []string `json:"tailscale_ips,omitempty"`
	Online         bool     `json:"online"`
	Active         bool     `json:"active,omitempty"`
	ExitNode       bool     `json:"exit_node,omitempty"`
	ExitNodeOption bool     `json:"exit_node_option,omitempty"`
	Expired        bool     `json:"expired,omitempty"`
	LastSeen       int64    `json:"last_seen,omitempty"`
}

type tailscaleStatusSnapshot struct {
	PID                int                     `json:"pid"`
	InstanceToken      string                  `json:"instance_token,omitempty"`
	BackendState       string                  `json:"backend_state"`
	Online             bool                    `json:"online"`
	Expired            bool                    `json:"expired,omitempty"`
	AuthURL            string                  `json:"auth_url,omitempty"`
	SelfHostname       string                  `json:"self_hostname,omitempty"`
	SelfDNSName        string                  `json:"self_dns_name,omitempty"`
	TailscaleIPs       []string                `json:"tailscale_ips,omitempty"`
	NetworkName        string                  `json:"network_name,omitempty"`
	MagicDNSSuffix     string                  `json:"magic_dns_suffix,omitempty"`
	PeersOnline        int                     `json:"peers_online"`
	PeersTotal         int                     `json:"peers_total"`
	Peers              []tailscalePeerSnapshot `json:"peers,omitempty"`
	ActiveExitNodeID   string                  `json:"active_exit_node_id,omitempty"`
	ActiveExitNodeName string                  `json:"active_exit_node_name,omitempty"`
	CanShareFiles      bool                    `json:"can_share_files,omitempty"`
	WaitingFileCount   int32                   `json:"waiting_file_count,omitempty"`
	UnreadFileCount    int32                   `json:"unread_file_count,omitempty"`
	ControlAvailable   bool                    `json:"control_available,omitempty"`
	UpdatedAt          string                  `json:"updated_at"`
}

func startTailscaleRuntime(ctx context.Context, instance *box.Box, statusPath, statusToken, ctrlAddr, ctrlToken string) func() {
	statusPath = strings.TrimSpace(statusPath)
	statusToken = strings.TrimSpace(statusToken)
	if instance == nil {
		return func() {}
	}
	epMgr := instance.Endpoint()
	var tsEp adapter.TailscaleEndpoint
	if epMgr != nil {
		for _, ep := range epMgr.Endpoints() {
			if candidate, ok := ep.(adapter.TailscaleEndpoint); ok {
				tsEp = candidate
				break
			}
		}
	}

	ctrlSrv, ctrlErr := newCoreControlServer(ctrlAddr, ctrlToken, tsEp)
	if ctrlErr != nil {
		fmt.Fprintf(os.Stderr, "WARN[0000] core control server failed on %s: %v\n", ctrlAddr, ctrlErr)
	}
	ctrlAvailable := ctrlSrv != nil

	if tsEp == nil {
		return func() {
			if ctrlSrv != nil {
				ctrlSrv.Close()
			}
		}
	}

	pid := os.Getpid()
	lastLoggedKey := ""
	writeSnapshot := func(st *adapter.TailscaleEndpointStatus) {
		if st == nil {
			return
		}
		snap := convertEndpointStatusSnapshot(pid, st)
		snap.InstanceToken = statusToken
		snap.ControlAvailable = ctrlAvailable
		if ctrlSrv != nil {
			ctrlSrv.UpdateStatus(snap)
		}
		if statusPath != "" {
			_ = writeStatusSnapshotAtomic(statusPath, snap)
		}
		logKey := fmt.Sprintf("%s|%v|%s|%s", snap.BackendState, snap.Online, strings.Join(snap.TailscaleIPs, ","), snap.AuthURL)
		if logKey != lastLoggedKey {
			lastLoggedKey = logKey
			if snap.AuthURL != "" {
				fmt.Fprintf(os.Stderr, "INFO[0000] endpoint/tailscale[tailscale-ep]: Waiting for authentication: %s\n", snap.AuthURL)
			} else if snap.BackendState != "" {
				fmt.Fprintf(os.Stderr, "INFO[0000] endpoint/tailscale[tailscale-ep]: state=%s online=%v ips=%v peers=%d/%d\n",
					snap.BackendState, snap.Online, snap.TailscaleIPs, snap.PeersOnline, snap.PeersTotal)
			}
		}
	}

	initialSnap := tailscaleStatusSnapshot{
		PID:              pid,
		InstanceToken:    statusToken,
		BackendState:     "Starting",
		ControlAvailable: ctrlAvailable,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	if ctrlSrv != nil {
		ctrlSrv.UpdateStatus(initialSnap)
	}
	if statusPath != "" {
		// Write an initial Starting snapshot immediately so UI transitions to "connecting" right away.
		_ = writeStatusSnapshotAtomic(statusPath, initialSnap)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = tsEp.SubscribeTailscaleStatus(ctx, writeSnapshot)
	}()

	if ctrlSrv != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tsEp.SubscribeTaildropInbox(ctx, func(inbox *adapter.TaildropInbox) {
				ctrlSrv.UpdateInbox(inbox)
			})
		}()
	}

	return func() {
		if ctrlSrv != nil {
			ctrlSrv.Close()
		}
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(1500 * time.Millisecond):
		}
	}
}

func convertEndpointStatusSnapshot(pid int, st *adapter.TailscaleEndpointStatus) tailscaleStatusSnapshot {
	snap := tailscaleStatusSnapshot{
		PID:              pid,
		BackendState:     strings.TrimSpace(st.BackendState),
		AuthURL:          strings.TrimSpace(st.AuthURL),
		NetworkName:      strings.TrimSpace(st.NetworkName),
		MagicDNSSuffix:   strings.TrimSpace(st.MagicDNSSuffix),
		CanShareFiles:    st.CanShareFiles,
		WaitingFileCount: st.WaitingFileCount,
		UnreadFileCount:  st.UnreadFileCount,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	if st.ExitNode != nil {
		snap.ActiveExitNodeID = strings.TrimSpace(st.ExitNode.StableID)
		snap.ActiveExitNodeName = strings.TrimSpace(st.ExitNode.HostName)
		if snap.ActiveExitNodeName == "" {
			snap.ActiveExitNodeName = strings.TrimSuffix(strings.TrimSpace(st.ExitNode.DNSName), ".")
		}
	}
	if st.Self != nil {
		snap.Online = st.Self.Online
		snap.Expired = st.Self.Expired
		snap.SelfHostname = strings.TrimSpace(st.Self.HostName)
		snap.SelfDNSName = strings.TrimSuffix(strings.TrimSpace(st.Self.DNSName), ".")
		for _, ip := range st.Self.TailscaleIPs {
			clean := strings.TrimSpace(ip)
			if clean != "" {
				snap.TailscaleIPs = append(snap.TailscaleIPs, clean)
			}
		}
	}
	for _, grp := range st.UserGroups {
		if grp == nil {
			continue
		}
		for _, p := range grp.Peers {
			if p == nil {
				continue
			}
			snap.PeersTotal++
			if p.Online {
				snap.PeersOnline++
			}
			peerSnap := tailscalePeerSnapshot{
				StableID:       strings.TrimSpace(p.StableID),
				Hostname:       strings.TrimSpace(p.HostName),
				DNSName:        strings.TrimSuffix(strings.TrimSpace(p.DNSName), "."),
				OS:             strings.TrimSpace(p.OS),
				Online:         p.Online,
				Active:         p.Active,
				ExitNode:       p.ExitNode,
				ExitNodeOption: p.ExitNodeOption,
				Expired:        p.Expired,
				LastSeen:       p.LastSeen,
			}
			for _, rawIP := range p.TailscaleIPs {
				clean := strings.TrimSpace(rawIP)
				if clean == "" {
					continue
				}
				peerSnap.TailscaleIPs = append(peerSnap.TailscaleIPs, clean)
				if strings.Contains(clean, ":") {
					if peerSnap.IPv6 == "" {
						peerSnap.IPv6 = clean
					}
				} else if peerSnap.IPv4 == "" {
					peerSnap.IPv4 = clean
				}
			}
			if peerSnap.Hostname == "" && peerSnap.DNSName != "" {
				peerSnap.Hostname = strings.SplitN(peerSnap.DNSName, ".", 2)[0]
			}
			snap.Peers = append(snap.Peers, peerSnap)
		}
	}
	sort.SliceStable(snap.Peers, func(i, j int) bool {
		if snap.Peers[i].Online != snap.Peers[j].Online {
			return snap.Peers[i].Online
		}
		return strings.ToLower(snap.Peers[i].Hostname) < strings.ToLower(snap.Peers[j].Hostname)
	})
	return snap
}

func writeStatusSnapshotAtomic(path string, snap tailscaleStatusSnapshot) error {
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	if info, lErr := os.Lstat(path); lErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink status path %s", path)
	}
	mode := statusSnapshotFileMode()
	tmp, err := os.CreateTemp(dir, ".ts-status-*")
	if err != nil {
		return fmt.Errorf("create temp status snapshot: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	// Transfer FD ownership before Close+Rename so there is no chmod/chown TOCTOU window or symlink follow.
	chownFileFD(tmp)
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

// Subscription aliases the v1.0 storage.SubscriptionRecord schema.
type Subscription = storage.SubscriptionRecord

func (s *Server) subscriptions() ([]Subscription, error) {
	if s.store == nil {
		return []Subscription{}, nil
	}
	return s.store.ListSubscriptions()
}

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := s.subscriptions()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}

	if r.Method == http.MethodDelete {
		id := strings.TrimSpace(r.PathValue("id"))
		if id == "" {
			http.Error(w, "subscription id required", http.StatusBadRequest)
			return
		}
		_ = s.store.SyncSubscriptionNodes(id, nil)
		err := s.store.DeleteSubscription(id)
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "subscription not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		list, err := s.subscriptions()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, list)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		URL             string `json:"url"`
		AutoUpdateHours int    `json:"auto_update_hours"`
		IntervalMinutes int    `json:"interval_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := url.ParseRequestURI(strings.TrimSpace(req.URL))
	if strings.TrimSpace(req.Name) == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "需要名称与有效的 HTTP(S) 订阅地址", http.StatusBadRequest)
		return
	}
	hours := req.AutoUpdateHours
	if hours <= 0 && req.IntervalMinutes > 0 {
		if req.IntervalMinutes < 5 {
			http.Error(w, "自动更新间隔不能小于 5 分钟", http.StatusBadRequest)
			return
		}
		hours = max(1, req.IntervalMinutes/60)
	}
	if hours < 0 {
		http.Error(w, "auto_update_hours cannot be negative", http.StatusBadRequest)
		return
	}

	sub := Subscription{
		ID:              strings.TrimSpace(req.ID),
		Name:            strings.TrimSpace(req.Name),
		URL:             u.String(),
		AutoUpdateHours: hours,
		Warnings:        []string{},
	}
	if sub.ID == "" {
		sub.ID = newRandomID("sub-")
	}
	if err := s.store.SaveSubscription(sub); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	list, err := s.subscriptions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "subscription id required", http.StatusBadRequest)
		return
	}
	existing, found, err := s.store.GetSubscription(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "subscription not found", http.StatusNotFound)
		return
	}
	var req struct {
		Name            string `json:"name"`
		URL             string `json:"url"`
		AutoUpdateHours *int   `json:"auto_update_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		existing.Name = strings.TrimSpace(req.Name)
	}
	if strings.TrimSpace(req.URL) != "" {
		u, err := url.ParseRequestURI(strings.TrimSpace(req.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			http.Error(w, "需要有效的 HTTP(S) 订阅地址", http.StatusBadRequest)
			return
		}
		existing.URL = u.String()
	}
	if req.AutoUpdateHours != nil {
		if *req.AutoUpdateHours < 0 {
			http.Error(w, "auto_update_hours cannot be negative", http.StatusBadRequest)
			return
		}
		existing.AutoUpdateHours = *req.AutoUpdateHours
	}
	if err := s.store.SaveSubscription(*existing); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, existing)
}

func (s *Server) refreshSubscription(ctx context.Context, v *Subscription) error {
	if v == nil || strings.TrimSpace(v.URL) == "" {
		return fmt.Errorf("subscription url is required")
	}
	if strings.TrimSpace(v.ID) == "" {
		v.ID = newRandomID("sub-")
	}

	client := safeHTTPClient(20 * time.Second)
	doFetch := func(c *http.Client) (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, v.URL, nil)
		if reqErr != nil {
			return nil, reqErr
		}
		req.Header.Set("User-Agent", "PrismRay/1.0.1")
		return c.Do(req)
	}
	resp, err := doFetch(client)
	if err != nil {
		// If direct fetch failed and the proxy core is running locally, retry via the local mixed port.
		if st := s.ensureOrchestrator().Status(); st.Running && st.MixedPort > 0 {
			if proxyURL, parseErr := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", st.MixedPort)); parseErr == nil {
				proxied := safeHTTPClient(20 * time.Second)
				proxied.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
				if pResp, pErr := doFetch(proxied); pErr == nil {
					resp, err = pResp, nil
				}
			}
		}
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	meta := config.ParseUserinfoHeader(resp.Header.Get("Subscription-Userinfo"))
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	res, err := config.ParseSubscriptionResilient(string(body))
	if err != nil {
		return err
	}
	if len(res.Nodes) == 0 {
		if len(res.Skipped) > 0 {
			return fmt.Errorf("subscription produced 0 valid nodes (%s)", res.Skipped[0].Reason)
		}
		return fmt.Errorf("subscription produced 0 valid nodes")
	}

	if res.Meta.TotalBytes > 0 || res.Meta.UploadBytes > 0 || res.Meta.DownloadBytes > 0 || res.Meta.ExpireUnix > 0 {
		if meta.TotalBytes == 0 {
			meta.TotalBytes = res.Meta.TotalBytes
		}
		if meta.UploadBytes == 0 {
			meta.UploadBytes = res.Meta.UploadBytes
		}
		if meta.DownloadBytes == 0 {
			meta.DownloadBytes = res.Meta.DownloadBytes
		}
		if meta.ExpireUnix == 0 {
			meta.ExpireUnix = res.Meta.ExpireUnix
		}
	}

	// Ensure deterministic fallback IDs within this subscription if nodes did not carry IDs.
	for i, n := range res.Nodes {
		n.SubID = v.ID
		if strings.TrimSpace(n.ID) == "" {
			n.ID = fmt.Sprintf("%s-%d", v.ID, i+1)
		}
	}

	if err := s.store.SyncSubscriptionNodes(v.ID, res.Nodes); err != nil {
		return err
	}

	v.UploadBytes = meta.UploadBytes
	v.DownloadBytes = meta.DownloadBytes
	v.TotalBytes = meta.TotalBytes
	v.ExpireUnix = meta.ExpireUnix
	v.ImportedCount = len(res.Nodes)
	v.SkippedCount = len(res.Skipped)
	v.Warnings = res.Warnings
	if v.Warnings == nil {
		v.Warnings = []string{}
	}
	v.LastUpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := s.store.SaveSubscription(*v); err != nil {
		return err
	}
	if s.ensureOrchestrator().Status().Running {
		s.opMu.Lock()
		_, _ = s.reconcileRuntime(ctx, s.activeNodeID, s.activeGroupID, s.tunEnabled)
		s.opMu.Unlock()
	}
	return nil
}

func (s *Server) handleRefreshSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	sub, found, err := s.store.GetSubscription(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "subscription not found", http.StatusNotFound)
		return
	}
	if err := s.refreshSubscription(r.Context(), sub); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

// RunMaintenance executes periodic background tasks for subscriptions, health monitoring, Kill Switch, and core update checks.
func (s *Server) RunMaintenance(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			subs, err := s.subscriptions()
			if err == nil {
				for i := range subs {
					if subs[i].AutoUpdateHours <= 0 {
						continue
					}
					last, parseErr := time.Parse(time.RFC3339, subs[i].LastUpdatedAt)
					if subs[i].LastUpdatedAt == "" || parseErr != nil || time.Since(last) >= time.Duration(subs[i].AutoUpdateHours)*time.Hour {
						_ = s.refreshSubscription(ctx, &subs[i])
					}
				}
			}
			s.maintainKillSwitch(ctx)
			s.maintainHealth(ctx)
			s.maintainCoreUpdates(ctx)
		}
	}
}

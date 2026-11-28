// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
)

// AppVersion and AppRepository identify the running PrismRay release for update checks.
var (
	AppVersion    = "1.0.1"
	AppRepository = "CRACKRAMMER/PrismRay"
	githubAPIBase = "https://api.github.com"
)

type AppUpdateAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256,omitempty"`
}

type AppUpdateCheckResult struct {
	CurrentVersion   string           `json:"current_version"`
	LatestVersion    string           `json:"latest_version,omitempty"`
	HasUpdate        bool             `json:"has_update"`
	Status           string           `json:"status"` // update_available | up_to_date | no_published_release | error
	Message          string           `json:"message,omitempty"`
	Prerelease       bool             `json:"prerelease,omitempty"`
	ReleaseName      string           `json:"release_name,omitempty"`
	ReleaseNotes     string           `json:"release_notes,omitempty"`
	PublishedAt      string           `json:"published_at,omitempty"`
	ReleaseURL       string           `json:"release_url,omitempty"`
	RecommendedAsset *AppUpdateAsset  `json:"recommended_asset,omitempty"`
	InstallHint      string           `json:"install_hint,omitempty"`
	Assets           []AppUpdateAsset `json:"assets,omitempty"`
	Platform         string           `json:"platform"`
	Mode             string           `json:"mode"`
	CheckedAt        string           `json:"checked_at"`
}

type ghReleasePayload struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	HTMLURL     string `json:"html_url"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	PublishedAt string `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

type parsedSemver struct {
	major int
	minor int
	patch int
	pre   string
}

func parseSemver(raw string) parsedSemver {
	clean := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(raw, "v"), "V"))
	if idx := strings.IndexByte(clean, '+'); idx >= 0 {
		clean = clean[:idx]
	}
	var pre string
	if idx := strings.IndexByte(clean, '-'); idx >= 0 {
		pre = clean[idx+1:]
		clean = clean[:idx]
	}
	parts := strings.Split(clean, ".")
	toInt := func(i int) int {
		if i >= len(parts) {
			return 0
		}
		n, _ := strconv.Atoi(parts[i])
		return n
	}
	return parsedSemver{
		major: toInt(0),
		minor: toInt(1),
		patch: toInt(2),
		pre:   pre,
	}
}

// compareSemver returns -1 if a < b, 0 if a == b, and 1 if a > b.
func compareSemver(a, b string) int {
	pa, pb := parseSemver(a), parseSemver(b)
	for _, pair := range [][2]int{{pa.major, pb.major}, {pa.minor, pb.minor}, {pa.patch, pb.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if pa.pre == pb.pre {
		return 0
	}
	if pa.pre == "" {
		return 1
	}
	if pb.pre == "" {
		return -1
	}
	aParts := strings.Split(pa.pre, ".")
	bParts := strings.Split(pb.pre, ".")
	limit := max(len(aParts), len(bParts))
	for i := 0; i < limit; i++ {
		if i >= len(aParts) {
			return -1
		}
		if i >= len(bParts) {
			return 1
		}
		ai, aErr := strconv.Atoi(aParts[i])
		bi, bErr := strconv.Atoi(bParts[i])
		if aErr == nil && bErr == nil {
			if ai < bi {
				return -1
			}
			if ai > bi {
				return 1
			}
			continue
		}
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}
	return 0
}

func isArchLinuxHost() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := os.Stat("/etc/arch-release")
	return err == nil
}

func pickRecommendedAsset(assets []AppUpdateAsset, goos, goarch, mode string, isArch bool) (*AppUpdateAsset, string) {
	findByMatchers := func(matchers ...func(name string) bool) *AppUpdateAsset {
		for _, match := range matchers {
			for i := range assets {
				if match(strings.ToLower(assets[i].Name)) {
					cp := assets[i]
					return &cp
				}
			}
		}
		return nil
	}

	if mode == authservice.ModeAndroid || goos == "android" {
		return findByMatchers(
			func(n string) bool { return strings.HasSuffix(n, ".apk") && strings.Contains(n, "arm64") },
			func(n string) bool { return strings.HasSuffix(n, ".apk") },
		), ""
	}

	if mode == authservice.ModeWeb {
		archTok := "x64"
		if goarch == "arm64" {
			archTok = "arm64"
		}
		return findByMatchers(
			func(n string) bool {
				return strings.Contains(n, "headless") && strings.Contains(n, archTok) && strings.HasSuffix(n, ".tar.gz")
			},
			func(n string) bool { return strings.Contains(n, "headless") && strings.HasSuffix(n, ".tar.gz") },
		), ""
	}

	switch goos {
	case "windows":
		return findByMatchers(
			func(n string) bool { return strings.HasSuffix(n, "-full.exe") },
			func(n string) bool { return strings.HasSuffix(n, "-full.msi") },
			func(n string) bool { return strings.HasSuffix(n, ".exe") },
			func(n string) bool { return strings.HasSuffix(n, ".msi") },
		), ""
	case "darwin":
		return findByMatchers(
			func(n string) bool { return strings.HasSuffix(n, "-full.dmg") },
			func(n string) bool { return strings.HasSuffix(n, ".dmg") },
		), ""
	case "linux":
		if isArch {
			asset := findByMatchers(
				func(n string) bool {
					return strings.HasPrefix(n, "prismray-") && !strings.HasPrefix(n, "prismray-server-") && strings.HasSuffix(n, ".pkg.tar.zst")
				},
				func(n string) bool { return strings.HasSuffix(n, "-full.appimage") },
			)
			return asset, ""
		}
		return findByMatchers(
			func(n string) bool { return strings.HasSuffix(n, "-full.appimage") },
			func(n string) bool { return strings.HasSuffix(n, ".appimage") },
			func(n string) bool { return strings.HasSuffix(n, "-full.deb") },
			func(n string) bool { return strings.HasSuffix(n, ".deb") },
			func(n string) bool { return strings.HasSuffix(n, "-full.rpm") },
		), ""
	default:
		return nil, ""
	}
}

func (s *Server) fetchGitHubURL(ctx context.Context, endpoint, accept string, limit int64) (int, []byte, error) {
	doReq := func(client *http.Client) (int, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("User-Agent", "PrismRay/"+AppVersion)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		raw, rErr := io.ReadAll(io.LimitReader(resp.Body, limit))
		if rErr != nil {
			return resp.StatusCode, raw, rErr
		}
		return resp.StatusCode, raw, nil
	}

	direct := s.safeHTTPClient(12 * time.Second)
	defer closeClientIdleConnections(direct)
	statusCode, body, err := doReq(direct)
	if err != nil {
		if st := s.ensureOrchestrator().Status(); st.Running && st.MixedPort > 0 {
			proxied := s.safeProxyHTTPClient(12*time.Second, st.MixedPort)
			defer closeClientIdleConnections(proxied)
			if pCode, pBody, pErr := doReq(proxied); pErr == nil {
				return pCode, pBody, nil
			}
		}
	}
	return statusCode, body, err
}

func (s *Server) fetchGitHubJSON(ctx context.Context, endpoint string) (int, []byte, error) {
	return s.fetchGitHubURL(ctx, endpoint, "application/vnd.github+json", 2<<20)
}

func parseSHA256Sums(body []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		digest := strings.ToLower(strings.TrimSpace(fields[0]))
		if len(digest) != 64 {
			continue
		}
		validHex := true
		for _, ch := range digest {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
				validHex = false
				break
			}
		}
		if !validHex {
			continue
		}
		name := strings.TrimPrefix(strings.TrimSpace(fields[1]), "*")
		name = path.Base(strings.ReplaceAll(name, "\\", "/"))
		if name != "" && name != "." && name != "/" {
			out[name] = digest
		}
	}
	return out
}

func (s *Server) fetchLatestAppRelease(ctx context.Context, includePrerelease bool) (*ghReleasePayload, int, error) {
	base := strings.TrimRight(githubAPIBase, "/")
	if !includePrerelease {
		code, body, err := s.fetchGitHubJSON(ctx, fmt.Sprintf("%s/repos/%s/releases/latest", base, AppRepository))
		if err != nil {
			return nil, 0, err
		}
		if code == http.StatusOK {
			var rel ghReleasePayload
			if decErr := json.Unmarshal(body, &rel); decErr != nil {
				return nil, code, decErr
			}
			return &rel, code, nil
		}
		if code != http.StatusNotFound {
			return nil, code, fmt.Errorf("GitHub Releases API returned HTTP %d", code)
		}
	}

	// Fallback to /releases when only prereleases exist or when prereleases are explicitly requested.
	code, body, err := s.fetchGitHubJSON(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=8", base, AppRepository))
	if err != nil {
		return nil, 0, err
	}
	if code == http.StatusNotFound {
		return nil, http.StatusNotFound, nil
	}
	if code != http.StatusOK {
		return nil, code, fmt.Errorf("GitHub Releases API returned HTTP %d", code)
	}
	var list []ghReleasePayload
	if decErr := json.Unmarshal(body, &list); decErr != nil {
		return nil, code, decErr
	}
	for i := range list {
		if !list[i].Draft {
			return &list[i], http.StatusOK, nil
		}
	}
	return nil, http.StatusNotFound, nil
}

func (s *Server) handleAppUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	includePre := r.URL.Query().Get("include_prerelease") == "1" || r.URL.Query().Get("include_prerelease") == "true"
	now := time.Now().UTC().Format(time.RFC3339)

	result := AppUpdateCheckResult{
		CurrentVersion: AppVersion,
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		Mode:           s.mode,
		CheckedAt:      now,
	}

	rel, statusCode, err := s.fetchLatestAppRelease(r.Context(), includePre)
	if err != nil {
		result.Status = "error"
		result.Message = err.Error()
		writeJSON(w, http.StatusOK, result)
		return
	}
	if rel == nil || statusCode == http.StatusNotFound {
		result.Status = "no_published_release"
		result.ReleaseURL = fmt.Sprintf("https://github.com/%s/releases", AppRepository)
		result.Message = "No published public release found yet (repository may be private or only draft releases exist)."
		writeJSON(w, http.StatusOK, result)
		return
	}

	latest := strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	result.LatestVersion = latest
	result.Prerelease = rel.Prerelease
	result.ReleaseName = rel.Name
	if result.ReleaseName == "" {
		result.ReleaseName = rel.TagName
	}
	result.ReleaseNotes = strings.TrimSpace(rel.Body)
	result.PublishedAt = rel.PublishedAt
	result.ReleaseURL = rel.HTMLURL
	if result.ReleaseURL == "" {
		result.ReleaseURL = fmt.Sprintf("https://github.com/%s/releases/tag/%s", AppRepository, rel.TagName)
	}

	shaByName := map[string]string{}
	for _, a := range rel.Assets {
		low := strings.ToLower(strings.TrimSpace(a.Name))
		if (low == "sha256sums.txt" || low == "checksums.txt" || strings.HasSuffix(low, ".sha256")) && strings.TrimSpace(a.BrowserDownloadURL) != "" {
			if code, body, cErr := s.fetchGitHubURL(r.Context(), a.BrowserDownloadURL, "text/plain", 256<<10); cErr == nil && code == http.StatusOK {
				for k, v := range parseSHA256Sums(body) {
					shaByName[k] = v
				}
			}
		}
	}

	assets := make([]AppUpdateAsset, 0, len(rel.Assets))
	for _, a := range rel.Assets {
		if strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.BrowserDownloadURL) == "" {
			continue
		}
		assets = append(assets, AppUpdateAsset{
			Name:        a.Name,
			DownloadURL: a.BrowserDownloadURL,
			Size:        a.Size,
			SHA256:      shaByName[a.Name],
		})
	}
	result.Assets = assets
	rec, hint := pickRecommendedAsset(assets, runtime.GOOS, runtime.GOARCH, s.mode, isArchLinuxHost())
	result.RecommendedAsset = rec
	result.InstallHint = hint

	if compareSemver(AppVersion, latest) < 0 {
		result.HasUpdate = true
		result.Status = "update_available"
	} else {
		result.HasUpdate = false
		result.Status = "up_to_date"
	}
	writeJSON(w, http.StatusOK, result)
}

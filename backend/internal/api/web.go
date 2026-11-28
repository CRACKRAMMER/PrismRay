// SPDX-License-Identifier: MPL-2.0
package api

import (
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
)

func appendUniqueOrigin(origins []string, origin string) []string {
	for _, existing := range origins {
		if existing == origin {
			return origins
		}
	}
	return append(origins, origin)
}

// SetWebDir serves only the compiled frontend, never the backend's data directory.
// Call before Start. os.Root prevents symlinks from escaping the asset directory.
func (s *Server) SetWebDir(directory string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	info, err := fs.Stat(root.FS(), "index.html")
	if err != nil || info.IsDir() {
		root.Close()
		return fmt.Errorf("web directory must contain a built index.html")
	}
	s.webRoot = root
	files := http.FileServerFS(root.FS())
	s.web = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path != "/" && path != "/index.html" && path != "/vite.svg" && path != "/favicon.svg" && (!strings.HasPrefix(path, "/assets/") || strings.HasSuffix(path, "/")) {
			http.NotFound(w, r)
			return
		}
		for _, part := range strings.Split(path, "/") {
			if strings.HasPrefix(part, ".") {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
	// Browsers send Origin on same-origin writes. Keep the standalone API restricted
	// to configured origins, adding the local web endpoint and active LAN bind host/IPs without wildcards.
	port := s.cfg.Server.Port
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]"} {
		s.cfg.Server.AllowedOrigins = appendUniqueOrigin(s.cfg.Server.AllowedOrigins, fmt.Sprintf("http://%s:%d", host, port))
	}
	bindHost := strings.TrimSpace(s.cfg.Server.Host)
	if bindHost != "" && bindHost != "127.0.0.1" && bindHost != "localhost" && bindHost != "::1" {
		if bindHost == "0.0.0.0" || bindHost == "::" {
			if addrs, aErr := net.InterfaceAddrs(); aErr == nil {
				for _, addr := range addrs {
					ipNet, ok := addr.(*net.IPNet)
					if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
						continue
					}
					if v4 := ipNet.IP.To4(); v4 != nil {
						s.cfg.Server.AllowedOrigins = appendUniqueOrigin(s.cfg.Server.AllowedOrigins, fmt.Sprintf("http://%s:%d", v4.String(), port))
					} else if ipNet.IP.To16() != nil && bindHost == "::" {
						s.cfg.Server.AllowedOrigins = appendUniqueOrigin(s.cfg.Server.AllowedOrigins, fmt.Sprintf("http://[%s]:%d", ipNet.IP.String(), port))
					}
				}
			}
		} else {
			if strings.Contains(bindHost, ":") && !strings.HasPrefix(bindHost, "[") {
				s.cfg.Server.AllowedOrigins = appendUniqueOrigin(s.cfg.Server.AllowedOrigins, fmt.Sprintf("http://[%s]:%d", bindHost, port))
			} else {
				s.cfg.Server.AllowedOrigins = appendUniqueOrigin(s.cfg.Server.AllowedOrigins, fmt.Sprintf("http://%s:%d", bindHost, port))
			}
		}
	}
	return nil
}

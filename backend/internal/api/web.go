// SPDX-License-Identifier: MPL-2.0
package api

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
)

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
		if path != "/" && path != "/index.html" && path != "/vite.svg" && (!strings.HasPrefix(path, "/assets/") || strings.HasSuffix(path, "/")) {
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
	// to configured origins, adding the local web endpoint without wildcards.
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]"} {
		s.cfg.Server.AllowedOrigins = append(s.cfg.Server.AllowedOrigins, fmt.Sprintf("http://%s:%d", host, s.cfg.Server.Port))
	}
	return nil
}

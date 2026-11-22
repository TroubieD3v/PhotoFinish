package server

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// notBuiltPage is served for every non-API path when the binary carries no
// UI build.
const notBuiltPage = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>PhotoFinish</title></head>
<body>
<p>The PhotoFinish API is running, but the web UI was not built into this binary.</p>
<p>Build it with <code>make ui</code>, then rebuild the binary with <code>make build</code>.</p>
</body>
</html>
`

// spa serves the built UI: existing files as they are, index.html for every
// other path (client-side routing), and a plain page without a UI build.
func (s *Server) spa() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		index, err := s.readUI("index.html")
		if err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(notBuiltPage))
			}
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name != "" && name != "index.html" && fs.ValidPath(name) {
			if fi, err := fs.Stat(s.ui, name); err == nil && fi.Mode().IsRegular() {
				if strings.HasPrefix(name, "assets/") {
					// Vite puts a content hash into every asset name.
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.ServeFileFS(w, r, s.ui, name)
				return
			}
			if strings.HasPrefix(name, "assets/") {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
	})
}

// readUI reads a file of the UI build.
func (s *Server) readUI(name string) ([]byte, error) {
	if s.ui == nil {
		return nil, fs.ErrNotExist
	}
	return fs.ReadFile(s.ui, name)
}

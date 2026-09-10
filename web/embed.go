//go:build webassets

package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var built embed.FS

// Handler serves immutable bundled assets with SPA route fallback. Assets that
// do not exist stay 404; no directory listings, filesystem paths or source maps.
func Handler() http.Handler {
	root, err := fs.Sub(built, "dist")
	if err != nil {
		panic("embedded frontend missing")
	}
	return assetHandler(root)
}

func assetHandler(root fs.FS) http.Handler {
	files := http.FileServerFS(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		clean := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if strings.HasSuffix(clean, ".map") || strings.HasPrefix(clean, ".") {
			http.NotFound(w, r)
			return
		}
		if clean != "" {
			if info, err := fs.Stat(root, clean); err == nil {
				if info.IsDir() {
					http.NotFound(w, r)
				} else {
					files.ServeHTTP(w, r)
				}
				return
			}
		}
		if path.Ext(clean) != "" || strings.HasPrefix(clean, "assets/") {
			http.NotFound(w, r)
			return
		}
		// Cloning avoids mutating the caller's URL/request; / maps to index.html.
		copy := r.Clone(r.Context())
		copiedURL := *r.URL
		copiedURL.Path = "/"
		copy.URL = &copiedURL
		files.ServeHTTP(w, copy)
	})
}

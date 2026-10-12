package server

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// webdist/app holds the built React UI (`make web`); webdist/index.html is a
// committed placeholder served when the UI has not been built.
//
//go:embed all:webdist
var webdist embed.FS

// webHandler serves the SPA, falling back to index.html for client-side routes.
func webHandler() http.Handler {
	sub, _ := fs.Sub(webdist, "webdist/app")
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		sub, _ = fs.Sub(webdist, "webdist")
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// Copyright (c) 2026 AllIsA1.
// SPDX-License-Identifier: MIT

package main

import (
	"embed"
	"encoding/json"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed ui
var pages embed.FS

type statusSource interface {
	status() status
	poke()
}

func newMux(src interface {
	memberLinks
	statusSource
}) http.Handler {
	inner := http.NewServeMux()
	inner.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, src.status()) })
	inner.HandleFunc("POST /sync", func(w http.ResponseWriter, r *http.Request) {
		src.poke()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux := http.NewServeMux()
	mux.Handle("POST /_lucx/seam/{mode}", SeamHandler(func(call SeamCall) (SeamReply, error) { return subscriptionSeam(call, src) }))
	mux.Handle("/api/", http.StripPrefix("/api", inner))
	mux.Handle("/ui/", pageHandler())
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func pageHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if strings.HasSuffix(name, "/") {
			name += "index.html"
		}
		clean := path.Clean(name)
		if !strings.HasPrefix(clean, "ui/") {
			http.NotFound(w, r)
			return
		}
		data, err := pages.ReadFile(clean)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		typ := mime.TypeByExtension(path.Ext(clean))
		if typ == "" {
			typ = "application/octet-stream"
		}
		w.Header().Set("Content-Type", typ)
		_, _ = w.Write(data)
	})
}

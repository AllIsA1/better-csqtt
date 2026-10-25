// Copyright (c) 2026 AllIsA1.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log"
	"path/filepath"
)

func main() {
	var api panelAPI
	if p, err := NewPanel(); err != nil {
		log.Printf("better-csqtt: %v; subscriptions are left as they are", err)
		api = failingPanel{err}
	} else {
		api = p
	}
	store, err := openManaged(filepath.Join(StateDir(), "members.json"))
	if err != nil {
		log.Fatalf("better-csqtt: %v", err)
	}
	s := newSyncer(api, store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.run(ctx)
	log.Print("better-csqtt plugin ready")
	if err := Serve(newMux(s)); err != nil {
		log.Fatal(err)
	}
}

type failingPanel struct{ err error }

func (f failingPanel) Do(context.Context, string, string, any, any) error { return f.err }

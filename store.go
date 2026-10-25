// Copyright (c) 2026 AllIsA1.
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// managedStore remembers which server members this plugin made (email -> password), so it never deletes or
// switches one that somebody made by hand.
type managedStore struct {
	path string
	mu   sync.Mutex
	m    map[string]string
}

func openManaged(path string) (*managedStore, error) {
	s := &managedStore{path: path, m: map[string]string{}}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.m); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *managedStore) snapshot() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}

func (s *managedStore) set(email, password string) {
	s.mu.Lock()
	s.m[email] = password
	s.mu.Unlock()
}

func (s *managedStore) drop(email string) {
	s.mu.Lock()
	delete(s.m, email)
	s.mu.Unlock()
}

func (s *managedStore) save() error {
	s.mu.Lock()
	raw, err := json.MarshalIndent(s.m, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

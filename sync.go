// Copyright (c) 2026 AllIsA1.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	syncEvery   = 30 * time.Second
	syncTimeout = 60 * time.Second
	webPort     = 46002
	pageSize    = 200
	maxPages    = 50
)

type panelAPI interface {
	Do(ctx context.Context, method, path string, in, out any) error
}

// target is the CSQTT inbound this plugin gives members to.
type target struct {
	InboundID int
	Remark    string
	MainPass  string // the panel's shared password: the one every subscription carries now
	WebPass   string
	Hashes    string
	Connect   string // where the server's web panel is: this machine, or the node's public address
	HostName  string // the host the links must name
}

type inboundRow struct {
	ID       int             `json:"id"`
	Protocol string          `json:"protocol"`
	Enable   bool            `json:"enable"`
	Remark   string          `json:"remark"`
	NodeID   *int            `json:"nodeId"`
	Settings json.RawMessage `json:"settings"`
}

type csqttSettings struct {
	Password string `json:"password"`
	WebPass  string `json:"webPass"`
	SubHost  string `json:"subHost"`
	Hashes   string `json:"vkHashes"`
}

// settingsOf reads the settings whether the API hands them as an object or as the JSON text inside a string.
func settingsOf(raw json.RawMessage) (csqttSettings, bool) {
	var s csqttSettings
	if len(raw) == 0 {
		return s, false
	}
	if raw[0] == '"' {
		var text string
		if json.Unmarshal(raw, &text) != nil || json.Unmarshal([]byte(text), &s) != nil {
			return s, false
		}
		return s, true
	}
	return s, json.Unmarshal(raw, &s) == nil
}

// findTarget picks the CSQTT inbound (the panel allows one per host). A node's inbound is reached at the
// public address its links name; the web panel must be open there.
func findTarget(rows []inboundRow) (target, error) {
	for _, r := range rows {
		if r.Protocol != "csqtt" || !r.Enable {
			continue
		}
		s, ok := settingsOf(r.Settings)
		if !ok || strings.TrimSpace(s.WebPass) == "" || strings.TrimSpace(s.Password) == "" {
			return target{}, errors.New("the CSQTT inbound has no web password or main password yet")
		}
		t := target{InboundID: r.ID, Remark: strings.TrimSpace(r.Remark), MainPass: s.Password, WebPass: s.WebPass,
			Hashes: strings.TrimSpace(s.Hashes), HostName: strings.TrimSpace(s.SubHost)}
		if r.NodeID != nil {
			if t.HostName == "" {
				return target{}, errors.New("the CSQTT inbound is on a node and has no public host to reach its web panel at")
			}
			t.Connect = t.HostName
		} else {
			t.Connect = "127.0.0.1"
		}
		return t, nil
	}
	return target{}, errors.New("no enabled CSQTT inbound")
}

type clientInfo struct {
	Email      string `json:"email"`
	SubID      string `json:"subId"`
	Enable     bool   `json:"enable"`
	TotalGB    int64  `json:"totalGB"`
	ExpiryTime int64  `json:"expiryTime"`
	InboundIDs []int  `json:"inboundIds"`
	Traffic    *struct {
		Up   int64 `json:"up"`
		Down int64 `json:"down"`
	} `json:"traffic"`
}

type clientPage struct {
	Items    []clientInfo `json:"items"`
	Filtered int          `json:"filtered"`
}

// usable: the panel gives a client that is switched off, expired or out of traffic no working link.
func (c clientInfo) usable(nowMs int64) bool {
	if !c.Enable {
		return false
	}
	if c.ExpiryTime > 0 && c.ExpiryTime <= nowMs {
		return false
	}
	if c.TotalGB > 0 && c.Traffic != nil && c.Traffic.Up+c.Traffic.Down >= c.TotalGB {
		return false
	}
	return true
}

// member is what the page shows about one person.
type member struct {
	Email    string `json:"email"`
	SubID    string `json:"subId"`
	Active   bool   `json:"active"`
	Sessions int    `json:"sessions"`
	State    string `json:"state"` // ok, created, off, taken, failed
}

// status is the last sync, for the page.
type status struct {
	CheckedAt time.Time `json:"checkedAt"`
	Server    string    `json:"server"`
	Error     string    `json:"error,omitempty"`
	Members   []member  `json:"members"`
}

// syncer keeps the server's member list in step with the panel's clients and knows each subscription's link.
type syncer struct {
	api     panelAPI
	store   *managedStore
	connect func(t target) csqttServer
	now     func() time.Time

	mu      sync.Mutex
	links   map[string]string // subscription id -> the member's link
	mains   map[string]bool   // the shared password(s) whose links are replaced
	st      status
	wake    chan struct{}
	running sync.Mutex
}

func newSyncer(api panelAPI, store *managedStore) *syncer {
	s := &syncer{api: api, store: store, now: time.Now, links: map[string]string{}, mains: map[string]bool{}, wake: make(chan struct{}, 1)}
	s.connect = func(t target) csqttServer {
		return newWebAPI(fmt.Sprintf("https://%s:%d", t.Connect, webPort), t.WebPass, t.HostName)
	}
	return s
}

func (s *syncer) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *syncer) run(ctx context.Context) {
	for {
		cctx, cancel := context.WithTimeout(ctx, syncTimeout)
		_ = s.syncOnce(cctx)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(syncEvery):
		case <-s.wake:
		}
	}
}

// snapshot returns what the seam needs: the member link of a subscription, and whether a password is the shared one.
func (s *syncer) linkFor(subID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[subID]
	return l, ok
}

func (s *syncer) isMain(password string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mains[password]
}

func (s *syncer) status() status {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.st
	out.Members = append([]member(nil), s.st.Members...)
	return out
}

func (s *syncer) fail(err error) error {
	s.mu.Lock()
	s.st.CheckedAt = s.now().UTC()
	s.st.Error = err.Error()
	s.mu.Unlock()
	return err
}

// syncOnce reads the panel, then makes the server agree. On any problem the links already known stay as they
// are and the subscriptions keep what they had: the panel's own shared link.
func (s *syncer) syncOnce(ctx context.Context) error {
	s.running.Lock()
	defer s.running.Unlock()
	var rows []inboundRow
	if err := s.api.Do(ctx, http.MethodGet, "/inbounds/list", nil, &rows); err != nil {
		return s.fail(fmt.Errorf("reading the panel's inbounds: %w", err))
	}
	t, err := findTarget(rows)
	if err != nil {
		s.mu.Lock()
		s.links, s.mains = map[string]string{}, map[string]bool{}
		s.mu.Unlock()
		return s.fail(err)
	}
	clients, err := s.loadClients(ctx, t.InboundID)
	if err != nil {
		return s.fail(fmt.Errorf("reading the panel's clients: %w", err))
	}
	srv := s.connect(t)
	existing, err := srv.List(ctx)
	if err != nil {
		return s.fail(fmt.Errorf("reading the CSQTT server's members: %w", err))
	}
	byName := map[string]serverClient{}
	for _, c := range existing {
		byName[c.Name] = c
	}
	managed := s.store.snapshot()
	nowMs := s.now().UnixMilli()

	links := map[string]string{}
	var members []member
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, c := range clients {
		if c.SubID == "" || c.Email == "" {
			continue
		}
		m := member{Email: c.Email, SubID: c.SubID}
		want := c.usable(nowMs)
		sc, have := byName[c.Email]
		switch {
		case !have:
			created, err := srv.Create(ctx, c.Email, t.Hashes)
			if err != nil || created.Password == "" {
				if err == nil {
					err = errors.New("the server returned no password")
				}
				note(fmt.Errorf("creating %s: %w", c.Email, err))
				m.State = "failed"
				members = append(members, m)
				continue
			}
			s.store.set(c.Email, created.Password)
			sc, m.State = created, "created"
			if !want {
				if err := srv.Toggle(ctx, created.Password); err != nil {
					note(fmt.Errorf("switching %s off: %w", c.Email, err))
				} else {
					sc.Active = false
				}
			}
		case managed[c.Email] == sc.Password:
			m.State = "ok"
			if sc.Active != want {
				if err := srv.Toggle(ctx, sc.Password); err != nil {
					note(fmt.Errorf("switching %s: %w", c.Email, err))
					m.State = "failed"
				} else {
					sc.Active = want
				}
			}
		default:
			m.State = "taken" // a member of that name the plugin did not make: its link is used, it is not touched
		}
		m.Active, m.Sessions = sc.Active, sc.ActiveSessions
		if sc.Link != "" {
			links[c.SubID] = sc.Link
		}
		members = append(members, m)
	}

	// members the plugin made for people who are no longer CSQTT clients of the panel
	present := map[string]bool{}
	for _, c := range clients {
		present[c.Email] = true
	}
	for email, pw := range managed {
		if present[email] {
			continue
		}
		if sc, ok := byName[email]; ok && sc.Password == pw {
			if err := srv.Delete(ctx, pw); err != nil {
				note(fmt.Errorf("deleting %s: %w", email, err))
				continue
			}
		}
		s.store.drop(email)
	}
	if err := s.store.save(); err != nil {
		note(fmt.Errorf("saving the plugin's list: %w", err))
	}

	sort.Slice(members, func(i, j int) bool { return members[i].Email < members[j].Email })
	s.mu.Lock()
	s.links = links
	s.mains = map[string]bool{t.MainPass: true}
	s.st = status{CheckedAt: s.now().UTC(), Server: srv.Where(), Members: members}
	if firstErr != nil {
		s.st.Error = firstErr.Error()
	}
	s.mu.Unlock()
	return firstErr
}

func (s *syncer) loadClients(ctx context.Context, inboundID int) ([]clientInfo, error) {
	var all []clientInfo
	for page := 1; page <= maxPages; page++ {
		var resp clientPage
		path := fmt.Sprintf("/clients/list/paged?protocol=csqtt&page=%d&pageSize=%d", page, pageSize)
		if err := s.api.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
			return nil, err
		}
		for _, c := range resp.Items {
			for _, id := range c.InboundIDs {
				if id == inboundID {
					all = append(all, c)
					break
				}
			}
		}
		if len(resp.Items) == 0 || page*pageSize >= resp.Filtered {
			break
		}
	}
	return all, nil
}

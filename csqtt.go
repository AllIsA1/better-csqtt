// Copyright (c) 2026 AllIsA1.
// SPDX-License-Identifier: MIT

// The CSQTT server's own web API (amurcanov/csqtt, the panel's CSQTT core): one password per person.
//
// The server lets one password hold one live session: a second device with the same password replaces the
// first. It also keeps a list of "clients" (members), each with a password of its own, its own tunnel address
// and its own limits, created through its web panel. This file talks to that web API.

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// csqttCipherSeed is the fixed seed the CSQTT links are sealed with (upstream v2.5.0, web_panel.rs).
const csqttCipherSeed = "csqtt-chiper-key"

// serverClient is one entry of the server's client list.
type serverClient struct {
	Password       string `json:"password"`
	Name           string `json:"name"`
	Active         bool   `json:"active"`
	ActiveSessions int    `json:"active_sessions"`
	Link           string `json:"link"`
	Expires        int64  `json:"expires"`
	VKHashes       string `json:"vk_hashes"`
}

// csqttServer is what the sync needs from the server's web API.
type csqttServer interface {
	Where() string
	List(ctx context.Context) ([]serverClient, error)
	Create(ctx context.Context, name, hashes string) (serverClient, error)
	Toggle(ctx context.Context, password string) error
	Delete(ctx context.Context, password string) error
}

// webAPI talks to the server's HTTPS web panel with the panel's web password as the API key.
type webAPI struct {
	base     string // https://127.0.0.1:46002
	key      string
	hostName string // what the server should take for the host of the links it makes
	client   *http.Client
}

func newWebAPI(base, key, hostName string) *webAPI {
	tr := &http.Transport{
		// The server's certificate is its own; the connection is to this machine or a server the operator named.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	return &webAPI{base: strings.TrimRight(base, "/"), key: key, hostName: hostName, client: &http.Client{Transport: tr, Timeout: 20 * time.Second}}
}

func (w *webAPI) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, w.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", w.key)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if w.hostName != "" {
		req.Host = w.hostName
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the CSQTT server answered HTTP %d for %s %s: %s", resp.StatusCode, method, path, strings.TrimSpace(string(raw)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// Where says which server this is, for the page.
func (w *webAPI) Where() string { return w.base }

func (w *webAPI) List(ctx context.Context) ([]serverClient, error) {
	var list []serverClient
	err := w.do(ctx, http.MethodGet, "/api/clients", nil, &list)
	return list, err
}

func (w *webAPI) Create(ctx context.Context, name, hashes string) (serverClient, error) {
	var created struct {
		Password string `json:"password"`
		Link     string `json:"link"`
	}
	// days 0: the panel decides when a client stops, the server keeps the entry until it is deleted.
	err := w.do(ctx, http.MethodPost, "/api/clients", map[string]any{"name": name, "days": 0, "hash": hashes}, &created)
	return serverClient{Password: created.Password, Name: name, Active: true, Link: created.Link, VKHashes: hashes}, err
}

func (w *webAPI) Toggle(ctx context.Context, password string) error {
	return w.do(ctx, http.MethodPost, "/api/clients/"+url.PathEscape(password)+"/toggle", nil, nil)
}

func (w *webAPI) Delete(ctx context.Context, password string) error {
	return w.do(ctx, http.MethodDelete, "/api/clients/"+url.PathEscape(password), nil, nil)
}

// linkPassword reads the password out of a csqtt:// link: the sealed form (csqtt://<base64url>) or the older
// plain one (csqtt://connect?...&password=...). An empty result says the link is not one it can read.
func linkPassword(link string) string {
	rest := strings.TrimPrefix(strings.TrimSpace(link), "csqtt://")
	if rest == link || rest == "" {
		return ""
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	payload := ""
	if strings.HasPrefix(rest, "connect?") {
		payload = rest
	} else if opened, err := openSealed(rest); err == nil {
		payload = opened
	} else {
		return ""
	}
	_, query, ok := strings.Cut(payload, "?")
	if !ok {
		return ""
	}
	for _, part := range strings.Split(query, "&") {
		if v, found := strings.CutPrefix(part, "password="); found {
			if pw, err := url.QueryUnescape(v); err == nil {
				return pw
			}
		}
	}
	return ""
}

// openSealed opens base64url(IV || AES-256-GCM(payload)), the key being SHA-256 of the seed.
func openSealed(b64 string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(b64, "="))
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(csqttCipherSeed))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("too short")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

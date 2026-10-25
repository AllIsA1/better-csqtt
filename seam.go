// Copyright (c) 2026 AllIsA1.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

const seamRoute = "/links/:subid"

// memberLinks is what the seam needs from the sync.
type memberLinks interface {
	linkFor(subID string) (string, bool)
	isMain(password string) bool
}

// swapLinks replaces the shared csqtt:// line (the one with the panel's main password) by the member's own,
// keeping the name the line had. Any other line stays as it is.
func swapLinks(lines []string, own string, m memberLinks) []string {
	out := make([]string, len(lines))
	copy(out, lines)
	done := false
	for i, l := range out {
		line := strings.TrimSpace(l)
		if !strings.HasPrefix(line, "csqtt://") || !m.isMain(linkPassword(line)) {
			continue
		}
		if done {
			out = slices.Delete(out, i, i+1) // the shared link twice: the member needs it once
			return swapLinks(out, own, m)
		}
		name := ""
		if at := strings.IndexByte(line, '#'); at >= 0 {
			name = line[at:]
		}
		ownBase := own
		if at := strings.IndexByte(ownBase, '#'); at >= 0 {
			ownBase, name = ownBase[:at], ownBase[at:]
		}
		out[i] = ownBase + name
		done = true
	}
	return out
}

// subscriptionSeam answers the seam declared in lucx-plugin.json. A subscription the plugin knows no member
// for, an answer it does not understand, or any doubt leaves the panel's answer untouched.
func subscriptionSeam(c SeamCall, m memberLinks) (SeamReply, error) {
	if c.Seam.Engine != "sub" || c.Seam.Mode != "after" {
		return SeamReply{}, fmt.Errorf("no seam %s/%s/%s is declared", c.Seam.Engine, c.Seam.Mode, c.Seam.Route)
	}
	if c.Seam.Route != seamRoute || c.Response == nil || c.Response.Status != http.StatusOK || len(c.Response.Body) == 0 {
		return Keep(), nil
	}
	subID := c.Request.Params["subid"]
	own, ok := m.linkFor(subID)
	if subID == "" || !ok {
		return Keep(), nil
	}
	if isHTML(c.Response) {
		body, changed := pageWithOwnLink(c.Response.Body, own, m)
		if !changed {
			return Keep(), nil
		}
		return Modify(ResponseChange{Body: Bytes(body)}), nil
	}
	text, wrapped, ok := subscriptionText(c.Response)
	if !ok {
		return Keep(), nil
	}
	original := strings.Split(strings.TrimRight(text, "\n"), "\n")
	lines := swapLinks(original, own, m)
	if slices.Equal(lines, original) {
		return Keep(), nil
	}
	changed := strings.Join(lines, "\n")
	if wrapped {
		changed = base64.StdEncoding.EncodeToString([]byte(changed))
	}
	return Modify(ResponseChange{Body: Bytes([]byte(changed))}), nil
}

func subscriptionText(r *SeamResponse) (text string, wrapped, ok bool) {
	if decoded, err := base64.StdEncoding.DecodeString(string(r.Body)); err == nil {
		return string(decoded), true, true
	}
	for name, values := range r.Headers {
		if !strings.EqualFold(name, "Content-Type") {
			continue
		}
		for _, v := range values {
			if strings.HasPrefix(strings.ToLower(v), "text/plain") && strings.Contains(string(r.Body), "://") {
				return string(r.Body), false, true
			}
		}
	}
	return "", false, false
}

const pageDataMarker = "window.__SUB_PAGE_DATA__="

func isHTML(r *SeamResponse) bool {
	for name, values := range r.Headers {
		if !strings.EqualFold(name, "Content-Type") {
			continue
		}
		for _, v := range values {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "text/html") {
				return true
			}
		}
	}
	return false
}

// pageWithOwnLink does the same to the list of links the panel embeds in the page of a browser.
func pageWithOwnLink(body []byte, own string, m memberLinks) ([]byte, bool) {
	at := bytes.Index(body, []byte(pageDataMarker))
	if at < 0 {
		return body, false
	}
	start := at + len(pageDataMarker)
	dec := json.NewDecoder(bytes.NewReader(body[start:]))
	var data map[string]json.RawMessage
	if err := dec.Decode(&data); err != nil {
		return body, false
	}
	end := start + int(dec.InputOffset())
	var links []string
	if raw, ok := data["links"]; !ok || json.Unmarshal(raw, &links) != nil {
		return body, false
	}
	lines := swapLinks(links, own, m)
	if slices.Equal(lines, links) {
		return body, false
	}
	rawLinks, err := json.Marshal(lines)
	if err != nil {
		return body, false
	}
	data["links"] = rawLinks
	out, err := json.Marshal(data)
	if err != nil {
		return body, false
	}
	var b bytes.Buffer
	b.Write(body[:start])
	b.Write(out)
	b.Write(body[end:])
	return b.Bytes(), true
}

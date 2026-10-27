// Copyright (c) 2026 AllIsA1.
// SPDX-License-Identifier: MIT

package main

import (
	"net/url"
	"strings"
)

// plainCsqttLink is the plain form of a sealed CSQTT link, csqtt://connect?v=2&host=..&peer=..&password=..[&hashes=a+b],
// which is what the proxy clients that fetch a subscription (YPtun for one) read; they skip the sealed form. Any other
// line (a plain CSQTT link included) is returned as it is. The name of the inbound goes after the last '#'; with no
// inbound name, the one the line had is kept.
func plainCsqttLink(line, inbound string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), "csqtt://")
	if !ok || rest == "" {
		return line
	}
	name := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest, name = rest[:i], rest[i+1:]
	}
	if inbound = strings.TrimSpace(inbound); inbound != "" {
		name = escapeUnreserved(inbound)
	}
	payload, err := openSealed(rest)
	if err != nil {
		return line
	}
	_, query, ok := strings.Cut(payload, "?")
	if !ok {
		return line
	}
	q, err := url.ParseQuery(strings.ReplaceAll(query, "+", "%2B")) // '+' separates the hashes: it is not a space
	if err != nil {
		return line
	}
	host, peer, password := q.Get("host"), q.Get("peer"), q.Get("password")
	if host == "" || peer == "" || password == "" {
		return line
	}
	out := "csqtt://connect?v=2&host=" + escapeUnreserved(host) + "&peer=" + escapeUnreserved(peer) +
		"&password=" + escapeUnreserved(password)
	if hashes := strings.FieldsFunc(q.Get("hashes"), func(r rune) bool { return strings.ContainsRune(",;+ \t\r\n", r) }); len(hashes) > 0 {
		for i, h := range hashes {
			hashes[i] = escapeUnreserved(h)
		}
		out += "&hashes=" + strings.Join(hashes, "+")
	}
	if name != "" {
		out += "#" + name
	}
	return out
}

// escapeUnreserved percent-encodes everything but the RFC 3986 unreserved characters, as YPtun itself does.
func escapeUnreserved(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

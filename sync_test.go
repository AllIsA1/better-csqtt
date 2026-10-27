// Copyright (c) 2026 AllIsA1.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seal makes a csqtt:// link the way the server does.
func seal(t *testing.T, payload string) string {
	t.Helper()
	key := sha256.Sum256([]byte(csqttCipherSeed))
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, gcm.NonceSize())
	copy(iv, "0123456789ab")
	return "csqtt://" + base64.RawURLEncoding.EncodeToString(append(iv, gcm.Seal(nil, iv, []byte(payload), nil)...))
}

func linkWith(t *testing.T, pw string) string {
	return seal(t, "connect?v=2&host=poland.example&peer=46000&password="+pw)
}

type fakeServer struct {
	t       *testing.T
	clients []serverClient
	calls   []string
	failOn  string
}

func (f *fakeServer) Where() string { return "fake" }

func (f *fakeServer) List(context.Context) ([]serverClient, error) {
	f.calls = append(f.calls, "list")
	if f.failOn == "list" {
		return nil, errors.New("down")
	}
	return append([]serverClient(nil), f.clients...), nil
}

func (f *fakeServer) Create(_ context.Context, name, hashes string) (serverClient, error) {
	f.calls = append(f.calls, "create "+name+" "+hashes)
	if f.failOn == "create" {
		return serverClient{}, errors.New("no")
	}
	pw := fmt.Sprintf("pw-%s-%d", strings.Split(name, "@")[0], len(f.clients))
	c := serverClient{Password: pw, Name: name, Active: true, Link: linkWith(f.t, pw)}
	f.clients = append(f.clients, c)
	return c, nil
}

func (f *fakeServer) Toggle(_ context.Context, pw string) error {
	f.calls = append(f.calls, "toggle "+pw)
	for i := range f.clients {
		if f.clients[i].Password == pw {
			f.clients[i].Active = !f.clients[i].Active
		}
	}
	return nil
}

func (f *fakeServer) Delete(_ context.Context, pw string) error {
	f.calls = append(f.calls, "delete "+pw)
	for i := range f.clients {
		if f.clients[i].Password == pw {
			f.clients = append(f.clients[:i], f.clients[i+1:]...)
			break
		}
	}
	return nil
}

type fakePanel struct {
	inbounds []map[string]any
	clients  []map[string]any
	fail     map[string]error
}

func (p *fakePanel) Do(_ context.Context, _, path string, _, out any) error {
	route := strings.SplitN(path, "?", 2)[0]
	if err := p.fail[route]; err != nil {
		return err
	}
	var obj any
	switch route {
	case "/inbounds/list":
		obj = p.inbounds
	case "/clients/list/paged":
		obj = map[string]any{"items": p.clients, "filtered": len(p.clients)}
	default:
		return errors.New("the plugin asked for " + path)
	}
	raw, _ := json.Marshal(obj)
	return json.Unmarshal(raw, out)
}

func csqttInbound(mutate ...func(map[string]any)) map[string]any {
	m := map[string]any{"id": 5, "protocol": "csqtt", "enable": true, "remark": "Poland",
		"settings": map[string]any{"password": "MAINPASS", "webPass": "web", "subHost": "poland.example", "vkHashes": "h1,h2"}}
	for _, f := range mutate {
		f(m)
	}
	return m
}

func pclient(email, sub string, mutate ...func(map[string]any)) map[string]any {
	m := map[string]any{"email": email, "subId": sub, "enable": true, "totalGB": 0, "expiryTime": 0, "inboundIds": []int{5}}
	for _, f := range mutate {
		f(m)
	}
	return m
}

type rig struct {
	t   *testing.T
	p   *fakePanel
	srv *fakeServer
	s   *syncer
}

func newRig(t *testing.T, clients ...map[string]any) *rig {
	t.Helper()
	store, err := openManaged(filepath.Join(t.TempDir(), "members.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, p: &fakePanel{inbounds: []map[string]any{csqttInbound()}, clients: clients, fail: map[string]error{}}, srv: &fakeServer{t: t}}
	r.s = newSyncer(r.p, store)
	r.s.connect = func(target) csqttServer { return r.srv }
	r.s.now = func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }
	return r
}

func (r *rig) sync() error { return r.s.syncOnce(context.Background()) }

func TestEveryClientGetsAMemberWithAPasswordOfItsOwn(t *testing.T) {
	r := newRig(t, pclient("anna@x", "subA"), pclient("boris@x", "subB"))
	if err := r.sync(); err != nil {
		t.Fatal(err)
	}
	a, okA := r.s.linkFor("subA")
	b, okB := r.s.linkFor("subB")
	if !okA || !okB || a == b || linkPassword(a) == linkPassword(b) || linkPassword(a) == "" {
		t.Fatalf("links: %q %q", a, b)
	}
	if got := strings.Join(r.srv.calls, ","); !strings.Contains(got, "create anna@x h1,h2") || !strings.Contains(got, "create boris@x h1,h2") {
		t.Errorf("calls = %s: a member per client, with the inbound's VK hashes", got)
	}
	if !r.s.isMain("MAINPASS") || r.s.isMain(linkPassword(a)) {
		t.Error("only the shared password is the one that is replaced")
	}
	if r.s.inboundName() != "Poland" {
		t.Errorf("inbound name = %q", r.s.inboundName())
	}
}

func TestASecondSyncChangesNothingOnTheServer(t *testing.T) {
	r := newRig(t, pclient("anna@x", "subA"))
	_ = r.sync()
	r.srv.calls = nil
	if err := r.sync(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.srv.calls, ","); got != "list" {
		t.Errorf("calls = %s", got)
	}
}

func TestAClientThatIsOffOrOutOfTrafficIsSwitchedOffOnTheServer(t *testing.T) {
	r := newRig(t, pclient("anna@x", "subA"), pclient("boris@x", "subB"))
	_ = r.sync()
	r.p.clients[0]["enable"] = false
	r.p.clients[1]["totalGB"] = 100
	r.p.clients[1]["traffic"] = map[string]any{"up": 60, "down": 60}
	r.srv.calls = nil
	_ = r.sync()
	for _, c := range r.srv.clients {
		if c.Active {
			t.Errorf("%s is still on", c.Name)
		}
	}
	// and back on when the panel allows it again
	r.p.clients[0]["enable"] = true
	_ = r.sync()
	if !r.srv.clients[0].Active {
		t.Error("the member was not switched on again")
	}
}

func TestAClientTakenOffTheInboundLosesTheMemberButNotOnesMadeByHand(t *testing.T) {
	r := newRig(t, pclient("anna@x", "subA"))
	r.srv.clients = []serverClient{{Password: "handmade", Name: "carol", Active: true}}
	_ = r.sync()
	r.p.clients = nil
	if err := r.sync(); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, c := range r.srv.clients {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "carol" {
		t.Errorf("members left = %v: only the plugin's own are removed", names)
	}
	if _, ok := r.s.linkFor("subA"); ok {
		t.Error("a link is still known for a client that is gone")
	}
}

func TestAMemberOfTheSameNameMadeByHandIsUsedAndNeverTouched(t *testing.T) {
	r := newRig(t, pclient("anna@x", "subA", func(m map[string]any) { m["enable"] = false }))
	hand := serverClient{Password: "handpw", Name: "anna@x", Active: true, Link: linkWith(t, "handpw")}
	r.srv.clients = []serverClient{hand}
	_ = r.sync()
	if l, _ := r.s.linkFor("subA"); linkPassword(l) != "handpw" {
		t.Errorf("link = %q", l)
	}
	for _, c := range r.srv.calls {
		if strings.HasPrefix(c, "toggle") || strings.HasPrefix(c, "delete") || strings.HasPrefix(c, "create") {
			t.Errorf("the plugin touched a member it did not make: %s", c)
		}
	}
}

func TestProblemsLeaveTheKnownLinksAndReportTheError(t *testing.T) {
	r := newRig(t, pclient("anna@x", "subA"))
	_ = r.sync()
	known, _ := r.s.linkFor("subA")
	r.srv.failOn = "list"
	if err := r.sync(); err == nil {
		t.Fatal("a failed list was not reported")
	}
	if got, _ := r.s.linkFor("subA"); got != known {
		t.Error("the known link was dropped because the server was down")
	}
	if r.s.status().Error == "" {
		t.Error("the page cannot see the problem")
	}
	r.srv.failOn = ""
	r.p.fail["/inbounds/list"] = errors.New("panel down")
	if err := r.sync(); err == nil {
		t.Error("a panel that does not answer was not reported")
	}
}

func TestNoCSQTTInboundMeansNothingIsChanged(t *testing.T) {
	r := newRig(t, pclient("anna@x", "subA"))
	r.p.inbounds = []map[string]any{{"id": 1, "protocol": "vless", "enable": true}}
	if err := r.sync(); err == nil || len(r.srv.calls) != 0 {
		t.Errorf("err = %v, calls = %v", err, r.srv.calls)
	}
	r.p.inbounds = []map[string]any{csqttInbound(func(m map[string]any) { m["enable"] = false })}
	if err := r.sync(); err == nil {
		t.Error("a disabled inbound counts")
	}
}

func TestAnInboundOnANodeIsReachedAtItsPublicHost(t *testing.T) {
	rows := []inboundRow{{ID: 5, Protocol: "csqtt", Enable: true, NodeID: new(int), Settings: mustJSON(map[string]any{"password": "m", "webPass": "w", "subHost": "poland.example"})}}
	tg, err := findTarget(rows)
	if err != nil || tg.Connect != "poland.example" {
		t.Fatalf("target = %+v, %v", tg, err)
	}
	rows[0].NodeID = nil
	if tg, _ := findTarget(rows); tg.Connect != "127.0.0.1" || tg.HostName != "poland.example" {
		t.Errorf("a local inbound is reached on this machine: %+v", tg)
	}
	rows[0].NodeID = new(int)
	rows[0].Settings = mustJSON(map[string]any{"password": "m", "webPass": "w"})
	if _, err := findTarget(rows); err == nil {
		t.Error("a node inbound without a public host cannot be reached")
	}
	// settings as the JSON text inside a string
	rows[0].NodeID = nil
	rows[0].Settings = mustJSON(`{"password":"m","webPass":"w"}`)
	if _, err := findTarget(rows); err != nil {
		t.Errorf("settings as a string: %v", err)
	}
}

func mustJSON(v any) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}

type linkSrc struct {
	links   map[string]string
	main    string
	inbound string
}

func (l linkSrc) linkFor(id string) (string, bool) { v, ok := l.links[id]; return v, ok }
func (l linkSrc) isMain(pw string) bool            { return pw == l.main }
func (l linkSrc) inboundName() string              { return l.inbound }

func TestTheSharedLinkIsReplacedByTheMembersOwnAndKeepsItsName(t *testing.T) {
	src := linkSrc{links: map[string]string{"s": linkWith(t, "own")}, main: "MAIN"}
	lines := []string{"vless://x#a", linkWith(t, "MAIN") + "#%D0%9F", linkWith(t, "someoneelse") + "#other", "openflux://v1/AAAA"}
	got := swapLinks(lines, src.links["s"], src)
	if linkPassword(got[1]) != "own" || !strings.HasSuffix(got[1], "#%D0%9F") {
		t.Errorf("shared line = %q", got[1])
	}
	if got[0] != lines[0] || got[2] != lines[2] || got[3] != lines[3] {
		t.Errorf("another line changed: %v", got)
	}
	// the shared link twice becomes one member link
	twice := swapLinks([]string{linkWith(t, "MAIN"), "vless://x", linkWith(t, "MAIN")}, src.links["s"], src)
	if len(twice) != 2 || linkPassword(twice[0]) != "own" {
		t.Errorf("twice = %v", twice)
	}
}

func TestLinkPasswordReadsSealedAndPlainLinksAndRefusesOthers(t *testing.T) {
	if linkPassword(linkWith(t, "p w")) != "p w" {
		t.Error("a sealed link")
	}
	if linkPassword("csqtt://connect?v=2&host=h&peer=1&password=plain%21") != "plain!" {
		t.Error("a plain link")
	}
	for _, bad := range []string{"", "vless://x", "csqtt://", "csqtt://not-base64!!", "csqtt://AAAA"} {
		if linkPassword(bad) != "" {
			t.Errorf("%q gave a password", bad)
		}
	}
}

func seamCall(subID string, body []byte, ct string) SeamCall {
	var c SeamCall
	c.Seam.Engine, c.Seam.Mode, c.Seam.Route = "sub", "after", seamRoute
	c.Request = SeamRequest{Method: "GET", Route: seamRoute, Params: map[string]string{"subid": subID}}
	c.Response = &SeamResponse{Status: 200, Body: body, Headers: map[string][]string{"Content-Type": {ct}}}
	return c
}

func TestTheSubscriptionAndItsPageCarryTheMembersLink(t *testing.T) {
	src := linkSrc{links: map[string]string{"s": linkWith(t, "own")}, main: "MAIN", inbound: "Польша 1"}
	raw := base64.StdEncoding.EncodeToString([]byte("vless://x#a\n" + linkWith(t, "MAIN") + "#N"))
	reply, err := subscriptionSeam(seamCall("s", []byte(raw), "text/plain; charset=utf-8"), src)
	if err != nil || reply.Action != "modify" {
		t.Fatalf("raw: %+v %v", reply, err)
	}
	dec, _ := base64.StdEncoding.DecodeString(string(*reply.Response.Body))
	if strings.Contains(string(dec), linkWith(t, "MAIN")) || strings.Contains(string(dec), linkWith(t, "own")) {
		t.Errorf("subscription = %q: a sealed link is still there", dec)
	}
	if !strings.Contains(string(dec), "csqtt://connect?v=2&host=poland.example&peer=46000&password=own#%D0%9F%D0%BE%D0%BB%D1%8C%D1%88%D0%B0%201") || strings.Contains(string(dec), "#N") {
		t.Errorf("subscription = %q: want the member's plain link named after the inbound", dec)
	}
	data, _ := json.Marshal(map[string]any{"links": []string{"vless://x#a", linkWith(t, "MAIN")}, "sId": "s"})
	page := []byte(`<html><head><script>window.__SUB_PAGE_DATA__=` + string(data) + `;</script></head></html>`)
	reply, _ = subscriptionSeam(seamCall("s", page, "text/html; charset=utf-8"), src)
	if reply.Action != "modify" {
		t.Fatalf("page: %+v", reply)
	}
	if strings.Contains(string(*reply.Response.Body), linkWith(t, "MAIN")) {
		t.Error("the shared link is still on the page")
	}
	// a subscription without a known member, and an answer that is not a subscription, are kept
	for name, c := range map[string]SeamCall{
		"unknown subscription": seamCall("zzz", []byte(raw), "text/plain"),
		"not found":            func() SeamCall { c := seamCall("s", []byte(raw), "text/plain"); c.Response.Status = 404; return c }(),
		"json":                 seamCall("s", []byte(`{"a":1}`), "application/json"),
	} {
		if reply, _ := subscriptionSeam(c, src); reply.Action != "keep" {
			t.Errorf("%s: %+v", name, reply)
		}
	}
}

func TestTheWebAPIClientSendsTheKeyAndTheHostTheLinksMustName(t *testing.T) {
	var gotKey, gotHost, gotMethod, gotPath string
	var body map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotHost, gotMethod, gotPath = r.Header.Get("x-api-key"), r.Host, r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[{"password":"p","name":"n","active":true,"active_sessions":2,"link":"csqtt://x"}]`))
			return
		}
		_, _ = w.Write([]byte(`{"password":"newpw","link":"csqtt://y"}`))
	}))
	defer srv.Close()
	api := newWebAPI(srv.URL, "secret", "poland.example")
	list, err := api.List(context.Background())
	if err != nil || len(list) != 1 || list[0].ActiveSessions != 2 || gotKey != "secret" || gotHost != "poland.example" || gotPath != "/api/clients" {
		t.Fatalf("list: %+v %v key=%q host=%q path=%q", list, err, gotKey, gotHost, gotPath)
	}
	c, err := api.Create(context.Background(), "anna@x", "h1,h2")
	if err != nil || c.Password != "newpw" || gotMethod != http.MethodPost || body["name"] != "anna@x" || body["hash"] != "h1,h2" || body["days"] != float64(0) {
		t.Fatalf("create: %+v %v method=%s body=%v", c, err, gotMethod, body)
	}
	if err := api.Toggle(context.Background(), "a b"); err != nil || gotPath != "/api/clients/a%20b/toggle" && gotPath != "/api/clients/a b/toggle" {
		t.Errorf("toggle: %v path=%q", err, gotPath)
	}
	if err := api.Delete(context.Background(), "p"); err != nil || gotMethod != http.MethodDelete {
		t.Errorf("delete: %v %s", err, gotMethod)
	}
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "nope", 401) }))
	defer bad.Close()
	if _, err := newWebAPI(bad.URL, "k", "").List(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a refused call: %v", err)
	}
}

func TestAnExpiredClientIsSwitchedOffAndAMemberThatChangedHandsIsNotDeleted(t *testing.T) {
	r := newRig(t, pclient("anna@x", "subA"), pclient("boris@x", "subB"))
	_ = r.sync()
	// anna's term ends; boris leaves, but somebody replaced his member by one of their own with the same name
	r.p.clients[0]["expiryTime"] = r.s.now().UnixMilli() - 1000
	r.p.clients = r.p.clients[:1]
	for i := range r.srv.clients {
		if r.srv.clients[i].Name == "boris@x" {
			r.srv.clients[i].Password = "somebody-elses"
		}
	}
	r.srv.calls = nil
	_ = r.sync()
	for _, c := range r.srv.calls {
		if strings.HasPrefix(c, "delete") {
			t.Errorf("a member that is not the plugin's any more was asked to be deleted: %s", c)
		}
	}
	var anna, boris *serverClient
	for i := range r.srv.clients {
		switch r.srv.clients[i].Name {
		case "anna@x":
			anna = &r.srv.clients[i]
		case "boris@x":
			boris = &r.srv.clients[i]
		}
	}
	if anna == nil || anna.Active {
		t.Errorf("an expired client is still on: %+v", anna)
	}
	if boris == nil || boris.Password != "somebody-elses" {
		t.Errorf("a member that is not the plugin's any more was deleted: %+v", boris)
	}
}

func TestTheInboundsHashesAreGivenToTheServerCommaSeparatedWithoutSpaces(t *testing.T) {
	for in, want := range map[string]string{
		"h1,h2": "h1,h2",
		"  aaaaaaaaaaaaaaaa \n bbbbbbbbbbbbbbbb ": "aaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbb",
		"a+b + c,d\te":    "a,b,c,d,e",
		"1 2 3 4 5 6 7 8": "1,2,3,4,5,6",
		"":                "",
		" , + ":           "",
	} {
		if got := serverHashes(in); got != want {
			t.Errorf("serverHashes(%q) = %q, want %q", in, got, want)
		}
	}
	r := newRig(t, pclient("admin", "subA"))
	r.p.inbounds = []map[string]any{csqttInbound(func(m map[string]any) {
		m["settings"].(map[string]any)["vkHashes"] = "aaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbb\ncccccccccccccccc"
	})}
	if err := r.sync(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.srv.calls, ","); !strings.Contains(got, "create admin aaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbb,cccccccccccccccc") {
		t.Errorf("calls = %s", got)
	}
}

func TestPlainLinkOfASealedOneKeepsPasswordAndHashesAndLeavesOthersAlone(t *testing.T) {
	sealed := seal(t, "connect?v=2&host=h.example&peer=9&password=a%2Bb~c%20d&hashes=aa+bb")
	if got, want := plainCsqttLink(sealed+"#Name", ""), "csqtt://connect?v=2&host=h.example&peer=9&password=a%2Bb~c%20d&hashes=aa+bb#Name"; got != want {
		t.Errorf("the line's own name is kept without an inbound name: got %q, want %q", got, want)
	}
	if got, want := plainCsqttLink(sealed+"#Name", "Poland 1"), "csqtt://connect?v=2&host=h.example&peer=9&password=a%2Bb~c%20d&hashes=aa+bb#Poland%201"; got != want {
		t.Errorf("the inbound's name follows the '#': got %q, want %q", got, want)
	}
	raw := seal(t, "connect?v=2&host=h&peer=1&password=a+b")
	if got, want := plainCsqttLink(raw, ""), "csqtt://connect?v=2&host=h&peer=1&password=a%2Bb"; got != want {
		t.Errorf("a raw plus in the sealed text is a plus: got %q, want %q", got, want)
	}
	for _, l := range []string{"vless://x#a", "csqtt://connect?v=2&host=h&peer=1&password=p", "csqtt://", "csqtt://notbase64!!", seal(t, "connect?v=2&host=&peer=1&password=p"), seal(t, "nothing")} {
		if got := plainCsqttLink(l, "Poland"); got != l {
			t.Errorf("plainCsqttLink(%q) = %q", l, got)
		}
	}
}

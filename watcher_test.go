package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/websocket"
)

func testConfig(pass string) *Config {
	return &Config{
		HTTPTimeout: 2 * time.Second, ShellyUser: "admin", ShellyPassword: pass,
		OfflineAfter: time.Minute, SleepyOfflineAfter: time.Hour,
	}
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// RFC 7616 Abschnitt 3.9.1, SHA-256-Beispiel.
func TestDigestRFC7616(t *testing.T) {
	c := digestChallenge{Realm: "http-auth@example.org", Qop: "auth, auth-int", Algorithm: "SHA-256",
		Nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", Opaque: "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"}
	h := c.authorization("Mufasa", "Circle of Life", "GET", "/dir/index.html", "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", 1)
	want := `response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"`
	if !strings.Contains(h, want) {
		t.Fatalf("falsche Digest-Antwort:\n%s", h)
	}
	p, ok := parseDigest(`Digest qop="auth", realm="shellyplus1pm-a8032ab12345", nonce="60dc59c6", algorithm=SHA-256`)
	if !ok || p.Realm != "shellyplus1pm-a8032ab12345" || p.Nonce != "60dc59c6" || p.Algorithm != "SHA-256" || p.Qop != "auth" {
		t.Fatalf("parseDigest: %+v", p)
	}
}

func TestGen1Version(t *testing.T) {
	for in, want := range map[string]string{
		"20230913-112003/v1.14.0-gcb84623":     "1.14.0",
		"20210115-103659/v1.9.4@e2732e05":      "1.9.4",
		"20220209-093700/v1.11.8-rc1-g1b4e8b1": "1.11.8-rc1",
		"":                                     "",
	} {
		if got := gen1Version(in); got != want {
			t.Errorf("gen1Version(%q) = %q, will %q", in, got, want)
		}
	}
}

// fakeGen1 simuliert ein Shelly 1 mit Basic-Auth (Benutzer admin/geheim).
func fakeGen1(t *testing.T, auth bool) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/shelly", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"type":"SHSW-1","mac":"E8DB84AABBCC","auth":%v,"fw":"20230913-112003/v1.14.0-gcb84623","discoverable":false,"longid":1,"num_outputs":1}`, auth)
	})
	protected := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if u, p, _ := r.BasicAuth(); auth && (u != "admin" || p != "geheim") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/settings", protected(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"name":"Flurlicht","device":{"type":"SHSW-1","mac":"E8DB84AABBCC","hostname":"shelly1-AABBCC"},"fw":"20230913-112003/v1.14.0-gcb84623"}`)
	}))
	mux.HandleFunc("/status", protected(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"wifi_sta":{"connected":true,"ssid":"Haus","ip":"192.168.1.20","rssi":-61},"cloud":{"enabled":false,"connected":false},
			"update":{"status":"pending","has_update":true,"new_version":"20240101-000000/v1.14.1-gabcdef0","old_version":"20230913-112003/v1.14.0-gcb84623","beta_version":"20230913-112003/v1.14.0-gcb84623"},"uptime":3600}`)
	}))
	return httptest.NewServer(mux)
}

// fakeGen2 simuliert ein Shelly Plus 1PM mit Digest-Auth (SHA-256), geprüft
// mit einer unabhängigen Implementierung.
func fakeGen2(t *testing.T, auth bool) *httptest.Server {
	const realm, nonce = "shellyplus1pm-a8032ab12345", "6544fc2e"
	mux := http.NewServeMux()
	mux.HandleFunc("/shelly", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"name":"Garage","id":"shellyplus1pm-a8032ab12345","mac":"A8032AB12345","slot":0,"model":"SNSW-001P16EU","gen":2,"fw_id":"20241011-114455/1.4.4-g6d2a586","ver":"1.4.4","app":"Plus1PM","auth_en":%v,"auth_domain":null}`, auth)
	})
	mux.HandleFunc("/rpc/Shelly.GetStatus", func(w http.ResponseWriter, r *http.Request) {
		if auth {
			f := map[string]string{}
			h := r.Header.Get("Authorization")
			for _, kv := range splitParams(strings.TrimPrefix(h, "Digest ")) {
				k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
				f[k] = strings.Trim(v, `"`)
			}
			ha1 := sha("admin:" + realm + ":geheim")
			ha2 := sha("GET:" + r.URL.Path)
			if f["response"] == "" || f["response"] != sha(ha1+":"+nonce+":"+f["nc"]+":"+f["cnonce"]+":auth:"+ha2) {
				w.Header().Set("WWW-Authenticate", `Digest qop="auth", realm="`+realm+`", nonce="`+nonce+`", algorithm=SHA-256`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		fmt.Fprint(w, `{"switch:0":{"id":0,"output":false},"sys":{"mac":"A8032AB12345","uptime":7200,"available_updates":{"beta":{"version":"1.5.0-beta1"},"stable":{"version":"1.4.5"}}},
			"wifi":{"sta_ip":"192.168.1.30","status":"got ip","ssid":"Haus","rssi":-55},"cloud":{"connected":true}}`)
	})
	return httptest.NewServer(mux)
}

func host(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }

func TestProbeGen1(t *testing.T) {
	srv := fakeGen1(t, true)
	defer srv.Close()

	// ohne Passwort: Modell + Firmware trotzdem erfasst
	d, err := newProber(testConfig(""), nil).probe(context.Background(), host(srv))
	if err != nil || d.Model != "SHSW-1" || d.FWVersion != "1.14.0" || d.AuthStatus != "missing" || d.Gen != 1 {
		t.Fatalf("ohne Passwort: %+v %v", d, err)
	}
	// falsches Passwort
	d, _ = newProber(testConfig("falsch"), nil).probe(context.Background(), host(srv))
	if d.AuthStatus != "failed" || d.FWVersion != "1.14.0" {
		t.Fatalf("falsches Passwort: %+v", d)
	}
	// richtiges Passwort: alle Details
	d, err = newProber(testConfig("geheim"), nil).probe(context.Background(), host(srv))
	if err != nil || d.AuthStatus != "ok" || d.Name != "Flurlicht" || d.ID != "shelly1-AABBCC" ||
		d.FWStable != "1.14.1" || d.FWBeta != "" || d.RSSI == nil || *d.RSSI != -61 || d.SSID != "Haus" {
		t.Fatalf("mit Passwort: %+v %v", d, err)
	}
}

func TestProbeGen2Digest(t *testing.T) {
	srv := fakeGen2(t, true)
	defer srv.Close()
	d, err := newProber(testConfig(""), nil).probe(context.Background(), host(srv))
	if err != nil || d.AuthStatus != "missing" || d.FWVersion != "1.4.4" || d.Model != "SNSW-001P16EU" {
		t.Fatalf("ohne Passwort: %+v %v", d, err)
	}
	d, _ = newProber(testConfig("falsch"), nil).probe(context.Background(), host(srv))
	if d.AuthStatus != "failed" {
		t.Fatalf("falsches Passwort: %+v", d)
	}
	d, err = newProber(testConfig("geheim"), nil).probe(context.Background(), host(srv))
	if err != nil || d.AuthStatus != "ok" || d.FWStable != "1.4.5" || d.FWBeta != "1.5.0-beta1" ||
		d.Uptime != 7200 || d.Cloud == nil || !*d.Cloud || d.Name != "Garage" || d.Gen != 2 {
		t.Fatalf("mit Passwort: %+v %v", d, err)
	}
	st := newStore(testConfig(""))
	st.apply(d, "scan")
	l := st.list()
	if len(l) != 1 || l[0].ModelName != "Shelly Plus 1PM" || l[0].Status != "online" {
		t.Fatalf("Store: %+v", l)
	}
}

func TestProbeNotShelly(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := newProber(testConfig(""), nil).probe(context.Background(), host(srv)); err != errNotShelly {
		t.Fatalf("404 sollte errNotShelly sein: %v", err)
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<html>DSM</html>") }))
	defer srv2.Close()
	if _, err := newProber(testConfig(""), nil).probe(context.Background(), host(srv2)); err != errNotShelly {
		t.Fatalf("HTML sollte errNotShelly sein: %v", err)
	}
}

func TestCoIoTParse(t *testing.T) {
	// CoAP: Ver 1, NON, TKL 0, Code 0.30, MsgID; Option 3332 (Delta 3332 = 14-ext: 3332-269=3063=0x0BF7)
	val := "SHHT-1#E8DB84AABBCC#2"
	pkt := []byte{0x50, 0x1e, 0x12, 0x34, 0xE0 | 13, 0x0B, 0xF7, byte(len(val) - 13)}
	pkt = append(pkt, val...)
	pkt = append(pkt, 0xff, '{', '}')
	typ, mac, ok := parseCoIoT(pkt)
	if !ok || typ != "SHHT-1" || mac != "E8DB84AABBCC" {
		t.Fatalf("parseCoIoT: %q %q %v", typ, mac, ok)
	}
	if _, _, ok := parseCoIoT([]byte{0x50, 0x1e}); ok {
		t.Fatal("zu kurzes Paket akzeptiert")
	}
}

func TestMDNSParse(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.StartAnswers()
	hdr := func(n string, typ dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(n), Type: typ, Class: dnsmessage.ClassINET, TTL: 120}
	}
	b.PTRResource(hdr("_shelly._tcp.local.", dnsmessage.TypePTR), dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("shellyplus1pm-a8032ab12345._shelly._tcp.local.")})
	b.StartAdditionals()
	b.AResource(hdr("shellyplus1pm-a8032ab12345.local.", dnsmessage.TypeA), dnsmessage.AResource{A: [4]byte{192, 168, 1, 30}})
	msg, _ := b.Finish()
	got := parseMDNSResponse(msg, netip.MustParseAddr("192.168.1.30"))
	if len(got) != 1 || got[0].String() != "192.168.1.30" {
		t.Fatalf("mDNS Shelly: %v", got)
	}
	// Fremdgerät (Drucker) ignorieren
	b = dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.StartAnswers()
	b.PTRResource(hdr("_http._tcp.local.", dnsmessage.TypePTR), dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("Drucker._http._tcp.local.")})
	msg, _ = b.Finish()
	if got := parseMDNSResponse(msg, netip.MustParseAddr("192.168.1.9")); len(got) != 0 {
		t.Fatalf("Drucker als Shelly erkannt: %v", got)
	}
}

func TestStoreHint(t *testing.T) {
	st := newStore(testConfig(""))
	st.hint(&Device{MAC: "AABBCC", IP: "1.2.3.4", Model: "SHHT-1"}, "coiot")
	if len(st.list()) != 0 {
		t.Fatal("Kurz-MAC darf kein Gerät anlegen")
	}
	st.hint(&Device{MAC: "E8DB84AABBCC", IP: "1.2.3.4", Gen: 1, Model: "SHHT-1"}, "coiot")
	l := st.list()
	if len(l) != 1 || !l[0].Sleepy || l[0].ModelName != "Shelly H&T" {
		t.Fatalf("Hinweis: %+v", l)
	}
	st.hint(&Device{MAC: "AABBCC", IP: "1.2.3.5"}, "coiot")
	if l = st.list(); l[0].IP != "1.2.3.5" {
		t.Fatalf("Kurz-MAC sollte bekanntes Gerät aktualisieren: %+v", l)
	}
}

// Ein schlafendes Plus H&T meldet sich per Outbound WebSocket, mit Passwort.
func TestOutboundWS(t *testing.T) {
	cfg := testConfig("geheim")
	st := newStore(cfg)
	w := &Web{cfg: cfg, st: st, sc: newScanner(cfg, nil)}
	srv := httptest.NewServer(w.handler())
	defer srv.Close()

	ws, err := websocket.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "", "http://shelly")
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	const realm = "shellyplusht-08b61fcd1234"
	for i := 0; i < 4; i++ {
		var req map[string]any
		if err := websocket.JSON.Receive(ws, &req); err != nil {
			t.Fatal(err)
		}
		id := req["id"]
		a, _ := req["auth"].(map[string]any)
		if a == nil {
			msg, _ := json.Marshal(map[string]any{"auth_type": "digest", "nonce": 1625038762, "nc": 1, "realm": realm, "algorithm": "SHA-256"})
			websocket.JSON.Send(ws, map[string]any{"id": id, "src": realm, "error": map[string]any{"code": 401, "message": string(msg)}})
			continue
		}
		ha1 := sha("admin:" + realm + ":geheim")
		want := sha(fmt.Sprintf("%s:1625038762:1:%.0f:auth:%s", ha1, a["cnonce"].(float64), sha("dummy_method:dummy_uri")))
		if a["response"] != want {
			t.Fatalf("falsche RPC-Auth: %v", a)
		}
		switch req["method"] {
		case "Shelly.GetDeviceInfo":
			websocket.JSON.Send(ws, map[string]any{"id": id, "src": realm, "result": map[string]any{
				"id": realm, "mac": "08B61FCD1234", "model": "SNSN-0013A", "gen": 2, "fw_id": "20241011-114455/1.4.4-g6d2a586",
				"ver": "1.4.4", "app": "PlusHT", "auth_en": true}})
		case "Shelly.GetStatus":
			websocket.JSON.Send(ws, map[string]any{"id": id, "src": realm, "result": map[string]any{
				"devicepower:0": map[string]any{"battery": map[string]any{"V": 5.9, "percent": 87}},
				"sys":           map[string]any{"uptime": 3, "available_updates": map[string]any{}}}})
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if l := st.list(); len(l) == 1 && l[0].Battery != nil {
			d := l[0]
			if d.Model != "SNSN-0013A" || d.FWVersion != "1.4.4" || !d.Sleepy || *d.Battery != 87 || d.AuthStatus != "ok" || d.ModelName != "Shelly Plus H&T" {
				t.Fatalf("WS-Gerät: %+v", d)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Gerät nicht per WebSocket erfasst: %+v", st.list())
}

func TestHosts(t *testing.T) {
	n := 0
	for range hosts(netip.MustParsePrefix("192.168.1.0/24")) {
		n++
	}
	if n != 254 {
		t.Fatalf("/24 sollte 254 Hosts haben, nicht %d", n)
	}
	n = 0
	for range hosts(netip.MustParsePrefix("192.168.1.7/32")) {
		n++
	}
	if n != 1 {
		t.Fatalf("/32: %d", n)
	}
}

func TestCmpVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.14.0", "1.9.4", 1}, {"1.4.4", "1.4.5", -1}, {"1.5.0-beta1", "1.5.0", -1},
		{"1.5.0", "1.4.9", 1}, {"1.2", "1.2.0", 0}, {"", "0.1", -1}, {"1.11.8-rc1", "1.11.8-rc2", -1},
	} {
		if got := cmpVersion(c.a, c.b); got != c.want {
			t.Errorf("cmpVersion(%q, %q) = %d, will %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAssessFirmware(t *testing.T) {
	ref := &FWRef{gen1: map[string]string{"SHSW-1": "1.14.0"}}
	devs := []Device{
		{MAC: "1", Gen: 1, Model: "SHSW-1", FWVersion: "1.12.1"},                          // Shelly-Liste
		{MAC: "2", Gen: 2, Model: "SNSW-001P16EU", FWVersion: "1.3.3"},                    // Netzvergleich
		{MAC: "3", Gen: 2, Model: "SNSW-001P16EU", FWVersion: "1.4.4"},                    // aktuell
		{MAC: "4", Gen: 3, Model: "S3SW-001X16EU", FWVersion: "1.5.0", FWStable: "1.6.1"}, // laut Gerät
		{MAC: "5", Gen: 2, Model: "SNSW-001P16EU", FWVersion: "1.5.0-beta2"},              // Beta zählt nicht als Referenz
	}
	assessFirmware(devs, ref)
	want := []struct {
		out    bool
		latest string
		src    string
	}{{true, "1.14.0", "shelly"}, {true, "1.4.4", "netz"}, {false, "", ""}, {true, "1.6.1", "gerät"}, {false, "", ""}}
	for i, w := range want {
		d := devs[i]
		if d.Outdated != w.out || d.FWLatest != w.latest || d.FWLatestSrc != w.src {
			t.Errorf("Gerät %s: outdated=%v latest=%q src=%q, will %+v", d.MAC, d.Outdated, d.FWLatest, d.FWLatestSrc, w)
		}
	}
}

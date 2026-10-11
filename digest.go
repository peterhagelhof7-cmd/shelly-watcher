package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// HTTP-Digest-Authentifizierung (RFC 7616), wie sie Gen2+-Shellys verlangen
// (SHA-256, Benutzer immer "admin").

type digestChallenge struct {
	Realm, Nonce, Qop, Algorithm, Opaque string
}

func parseDigest(h string) (digestChallenge, bool) {
	var c digestChallenge
	if len(h) < 7 || !strings.EqualFold(h[:7], "digest ") {
		return c, false
	}
	for _, kv := range splitParams(h[7:]) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "realm":
			c.Realm = v
		case "nonce":
			c.Nonce = v
		case "qop":
			c.Qop = v
		case "algorithm":
			c.Algorithm = v
		case "opaque":
			c.Opaque = v
		}
	}
	return c, c.Nonce != ""
}

// splitParams trennt an Kommas außerhalb von Anführungszeichen.
func splitParams(s string) []string {
	var out []string
	quoted, start := false, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

func digestHash(alg string) func(string) string {
	if strings.HasPrefix(strings.ToUpper(alg), "SHA-256") {
		return func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	}
	return func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
}

func (c digestChallenge) authorization(user, pass, method, uri, cnonce string, nc int) string {
	h := digestHash(c.Algorithm)
	ha1 := h(user + ":" + c.Realm + ":" + pass)
	ha2 := h(method + ":" + uri)
	ncs := fmt.Sprintf("%08x", nc)
	var b strings.Builder
	fmt.Fprintf(&b, `Digest username="%s", realm="%s", nonce="%s", uri="%s"`, user, c.Realm, c.Nonce, uri)
	if c.Algorithm != "" {
		fmt.Fprintf(&b, ", algorithm=%s", c.Algorithm)
	}
	if hasQopAuth(c.Qop) {
		resp := h(ha1 + ":" + c.Nonce + ":" + ncs + ":" + cnonce + ":auth:" + ha2)
		fmt.Fprintf(&b, `, response="%s", qop=auth, nc=%s, cnonce="%s"`, resp, ncs, cnonce)
	} else {
		fmt.Fprintf(&b, `, response="%s"`, h(ha1+":"+c.Nonce+":"+ha2))
	}
	if c.Opaque != "" {
		fmt.Fprintf(&b, `, opaque="%s"`, c.Opaque)
	}
	return b.String()
}

func hasQopAuth(q string) bool {
	for _, p := range strings.Split(q, ",") {
		if strings.TrimSpace(p) == "auth" {
			return true
		}
	}
	return false
}

// rpcAuth baut das "auth"-Objekt für Gen2+-JSON-RPC über WebSocket.
// Siehe Shelly-Doku "Authentication": ha2 ist fest sha256("dummy_method:dummy_uri").
// nc ist dort immer 1, cnonce eine Zahl.
func rpcAuth(user, pass, realm string, nonce, cnonce int64) map[string]any {
	h := digestHash("SHA-256")
	ha1 := h(user + ":" + realm + ":" + pass)
	ha2 := h("dummy_method:dummy_uri")
	resp := h(fmt.Sprintf("%s:%d:1:%d:auth:%s", ha1, nonce, cnonce, ha2))
	return map[string]any{
		"realm": realm, "username": user, "nonce": nonce, "cnonce": cnonce,
		"response": resp, "algorithm": "SHA-256",
	}
}

func newCnonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

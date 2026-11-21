package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Gerätenamen direkt auf dem Shelly setzen. Der Name liegt auf dem Gerät
// selbst (Gen1: /settings name, Gen2+: Sys-Konfiguration device.name), der
// Watcher liest ihn nur aus. So bleibt er auch in der Shelly-App und auf der
// Geräte-Weboberfläche gleich.

const maxNameLen = 64

var errOtherDevice = errors.New("unter dieser IP antwortet inzwischen ein anderes Gerät")

// cleanName entfernt Steuerzeichen und überflüssige Leerzeichen.
func cleanName(s string) (string, bool) {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	return s, utf8.RuneCountInString(s) <= maxNameLen
}

// setName schreibt den Namen auf das Gerät. Vorher wird über /shelly geprüft,
// dass unter der IP noch das erwartete Gerät antwortet. Ein leerer Name
// löscht den Gerätenamen.
func (p *Prober) setName(ctx context.Context, ip, mac string, gen int, name string) error {
	var si shellyInfo
	if err := p.get(ctx, ip, "/shelly", authNone, &si); err != nil {
		return err
	}
	if normMAC(si.MAC) != normMAC(mac) {
		return errOtherDevice
	}
	var resp json.RawMessage
	if gen >= 2 {
		var v any = name
		if name == "" {
			v = nil
		}
		cfg, _ := json.Marshal(map[string]any{"device": map[string]any{"name": v}})
		return p.get(ctx, ip, "/rpc/Sys.SetConfig?config="+url.QueryEscape(string(cfg)), authDigest, &resp)
	}
	return p.get(ctx, ip, "/settings?name="+url.QueryEscape(name), authBasic, &resp)
}

// setName übernimmt den Namen im Store, auch einen leeren (apply übernimmt
// leere Werte bewusst nicht).
func (s *Store) setName(mac, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devs[normMAC(mac)]; ok {
		d.Name = name
		s.dirty = true
	}
}

func (w *Web) rename(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(http.MaxBytesReader(rw, r.Body, 4096)).Decode(&req) != nil {
		http.Error(rw, "ungültige Anfrage", http.StatusBadRequest)
		return
	}
	name, ok := cleanName(req.Name)
	if !ok {
		http.Error(rw, "Name ist zu lang (höchstens 64 Zeichen)", http.StatusBadRequest)
		return
	}
	d, found := w.st.get(r.PathValue("mac"))
	switch {
	case !found:
		http.NotFound(rw, r)
		return
	case d.Status != "online" || d.IP == "":
		http.Error(rw, "Gerät ist nicht online (Akkugeräte erst aufwecken)", http.StatusConflict)
		return
	case d.AuthStatus == "missing" || d.AuthStatus == "failed":
		http.Error(rw, "Ohne gültiges Shelly-Passwort kann der Name nicht gesetzt werden", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*w.cfg.Get().HTTPTimeout)
	defer cancel()
	if err := w.pr.setName(ctx, d.IP, d.MAC, d.Gen, name); err != nil {
		http.Error(rw, "Gerät hat den Namen nicht übernommen: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.st.setName(d.MAC, name)
	rw.WriteHeader(http.StatusNoContent)
}

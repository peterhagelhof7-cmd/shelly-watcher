package main

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Device ist alles, was wir über ein Shelly wissen. Schlüssel ist die MAC.
type Device struct {
	MAC       string `json:"mac"`
	ID        string `json:"id,omitempty"` // z.B. shellyplus1pm-a8032ab12345
	IP        string `json:"ip"`
	Gen       int    `json:"gen"`
	Model     string `json:"model"`      // Typ-/Modellcode, z.B. SHSW-1, SNSW-001P16EU
	ModelName string `json:"model_name"` // lesbarer Name, z.B. "Shelly Plus 1PM"
	App       string `json:"app,omitempty"`
	Name      string `json:"name,omitempty"` // vom Nutzer vergebener Gerätename

	FW         string `json:"fw"`         // kompletter Firmware-String
	FWVersion  string `json:"fw_version"` // nur die Version, z.B. 1.14.0
	FWStable   string `json:"fw_update,omitempty"`
	FWBeta     string `json:"fw_beta,omitempty"`
	AuthEnable bool   `json:"auth_enabled"`
	AuthStatus string `json:"auth_status"` // none | ok | missing | failed

	SSID     string    `json:"ssid,omitempty"`
	RSSI     *int      `json:"rssi,omitempty"`
	Uptime   int64     `json:"uptime,omitempty"`
	Battery  *int      `json:"battery,omitempty"`
	Cloud    *bool     `json:"cloud,omitempty"`
	Sleepy   bool      `json:"sleepy"`
	Sources  []string  `json:"sources"`
	FirstSee time.Time `json:"first_seen"`
	LastSeen time.Time `json:"last_seen"`
	LastErr  string    `json:"last_error,omitempty"`

	// berechnet bei jeder Ausgabe
	Status      string `json:"status"`                  // online | offline | sleeping
	Outdated    bool   `json:"fw_outdated"`             // Firmware älter als neueste bekannte
	FWLatest    string `json:"fw_latest,omitempty"`     // neueste bekannte stabile Version
	FWLatestSrc string `json:"fw_latest_src,omitempty"` // gerät | shelly | netz
}

type Store struct {
	mu      sync.Mutex
	devs    map[string]*Device
	path    string
	dirty   bool
	offline time.Duration
	sleepy  time.Duration
	ref     *FWRef
}

func newStore(cfg *Config) *Store {
	s := &Store{devs: map[string]*Device{}, offline: cfg.OfflineAfter, sleepy: cfg.SleepyOfflineAfter}
	if cfg.DataDir != "" {
		s.path = filepath.Join(cfg.DataDir, "devices.json")
	}
	return s
}

func normMAC(m string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", "-", "").Replace(m))
}

// apply übernimmt eine Beobachtung. Leere Felder in obs überschreiben nichts.
func (s *Store) apply(obs *Device, source string) {
	key := normMAC(obs.MAC)
	if key == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devs[key]
	if !ok {
		d = &Device{MAC: key, FirstSee: now}
		s.devs[key] = d
		log.Printf("neues Gerät: %s %s (%s) fw %s via %s", key, obs.Model, obs.IP, obs.FWVersion, source)
	}
	s.setIP(d, obs.IP)
	setStr(&d.ID, obs.ID)
	setStr(&d.Model, obs.Model)
	setStr(&d.App, obs.App)
	setStr(&d.Name, obs.Name)
	setStr(&d.FW, obs.FW)
	setStr(&d.FWVersion, obs.FWVersion)
	setStr(&d.SSID, obs.SSID)
	setStr(&d.AuthStatus, obs.AuthStatus)
	if obs.Gen != 0 {
		d.Gen = obs.Gen
	}
	// Update-Info gilt nur, wenn wir den Status wirklich lesen konnten;
	// leer heißt dann "kein Update verfügbar".
	if obs.AuthStatus == "ok" || obs.AuthStatus == "none" {
		d.FWStable, d.FWBeta = obs.FWStable, obs.FWBeta
	}
	if obs.AuthStatus != "" {
		d.AuthEnable = obs.AuthEnable
	}
	if obs.RSSI != nil {
		d.RSSI = obs.RSSI
	}
	if obs.Uptime != 0 {
		d.Uptime = obs.Uptime
	}
	if obs.Battery != nil {
		d.Battery = obs.Battery
	}
	if obs.Cloud != nil {
		d.Cloud = obs.Cloud
	}
	d.Sleepy = d.Sleepy || obs.Sleepy || d.Battery != nil || sleepyModels[d.Model]
	if source != "" && source != "poll" && !slices.Contains(d.Sources, source) {
		d.Sources = append(d.Sources, source)
		sort.Strings(d.Sources)
	}
	d.LastSeen = now
	d.LastErr = obs.LastErr
	s.dirty = true
}

func ipLess(a, b string) bool {
	pa, ea := netip.ParseAddr(a)
	pb, eb := netip.ParseAddr(b)
	if ea != nil || eb != nil {
		return a < b
	}
	return pa.Less(pb)
}

func setStr(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

// hint verarbeitet einen schwachen Lebenszeichen-Hinweis (z.B. CoIoT): ein
// bekanntes Gerät gilt als gesehen; ein neues wird nur mit vollständiger MAC
// angelegt (manche Firmware meldet nur die letzten 6 Stellen).
func (s *Store) hint(obs *Device, source string) {
	mac := normMAC(obs.MAC)
	s.mu.Lock()
	var d *Device
	switch len(mac) {
	case 12:
		d = s.devs[mac]
	case 6:
		for k, o := range s.devs {
			if strings.HasSuffix(k, mac) {
				d = o
				break
			}
		}
	}
	if d != nil {
		d.LastSeen = time.Now()
		s.setIP(d, obs.IP)
		if source != "" && !slices.Contains(d.Sources, source) {
			d.Sources = append(d.Sources, source)
			sort.Strings(d.Sources)
		}
		s.dirty = true
	}
	s.mu.Unlock()
	if d == nil && len(mac) == 12 {
		obs.Sleepy = sleepyModels[obs.Model]
		obs.LastErr = "nur per " + source + " gesehen, Details folgen beim nächsten Aufwachen"
		s.apply(obs, source)
	}
}

// setIP ordnet dem Gerät seine aktuelle IP zu. Geräte werden über die MAC
// geführt; wechselt die IP (DHCP), bleibt es derselbe Eintrag. Hatte ein
// anderes Gerät diese IP noch eingetragen, ist sie dort veraltet und wird
// gelöscht, damit nie zwei Einträge dieselbe IP zeigen. Aufrufer hält s.mu.
func (s *Store) setIP(d *Device, ip string) {
	if ip == "" || d.IP == ip {
		return
	}
	for _, o := range s.devs {
		if o != d && o.IP == ip {
			o.IP = ""
		}
	}
	d.IP = ip
}

// macAt liefert die MAC des Geräts, das unter dieser IP geführt wird.
func (s *Store) macAt(ip string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, d := range s.devs {
		if d.IP == ip {
			return k
		}
	}
	return ""
}

// failed vermerkt einen fehlgeschlagenen Abruf für das Gerät unter dieser IP.
// Rückgabe true, wenn es vorher fehlerfrei war, also gerade erst verloren ging.
func (s *Store) failed(ip string, err error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	lost := false
	for _, d := range s.devs {
		if d.IP == ip {
			lost = lost || d.LastErr == ""
			d.LastErr = err.Error()
		}
	}
	return lost
}

func (s *Store) remove(mac string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normMAC(mac)
	if _, ok := s.devs[key]; !ok {
		return false
	}
	delete(s.devs, key)
	s.dirty = true
	return true
}

// list liefert Kopien aller Geräte mit berechnetem Status, sortiert nach IP.
func (s *Store) list() []Device {
	now := time.Now()
	s.mu.Lock()
	out := make([]Device, 0, len(s.devs))
	for _, d := range s.devs {
		c := *d
		c.Sources = slices.Clone(d.Sources)
		c.Status = s.status(d, now)
		c.ModelName = modelName(d.Model, d.App) // immer aktuell, auch nach Tabellen-Update
		out = append(out, c)
	}
	s.mu.Unlock()
	assessFirmware(out, s.ref)
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out
}

func (s *Store) status(d *Device, now time.Time) string {
	age := now.Sub(d.LastSeen)
	switch {
	case age <= s.offline:
		return "online"
	case d.Sleepy && age <= s.sleepy:
		return "sleeping"
	default:
		return "offline"
	}
}

// pollTargets liefert die IPs aller nicht schlafenden Geräte.
func (s *Store) pollTargets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ips []string
	for _, d := range s.devs {
		if d.IP != "" && !d.Sleepy {
			ips = append(ips, d.IP)
		}
	}
	return ips
}

func (s *Store) load() {
	if s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Gerätedatei nicht lesbar: %v", err)
		}
		return
	}
	var list []*Device
	if err := json.Unmarshal(b, &list); err != nil {
		log.Printf("Gerätedatei defekt, starte leer: %v", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range list {
		if d.MAC != "" {
			d.Status, d.Outdated, d.FWLatest, d.FWLatestSrc = "", false, "", ""
			s.devs[normMAC(d.MAC)] = d
		}
	}
	log.Printf("%d Geräte aus %s geladen", len(list), s.path)
}

// save schreibt atomar (tmp + rename), aber nur wenn sich etwas geändert hat.
func (s *Store) save() {
	if s.path == "" {
		return
	}
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return
	}
	list := make([]*Device, 0, len(s.devs))
	for _, d := range s.devs {
		c := *d
		list = append(list, &c)
	}
	s.dirty = false
	s.mu.Unlock()

	b, err := json.MarshalIndent(list, "", " ")
	if err == nil {
		tmp := s.path + ".tmp"
		if err = os.WriteFile(tmp, b, 0o644); err == nil {
			err = os.Rename(tmp, s.path)
		}
	}
	if err != nil {
		log.Printf("Speichern fehlgeschlagen (läuft ohne Persistenz weiter): %v", err)
	}
}

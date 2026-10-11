package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const repoURL = "https://github.com/peterhagelhof7-cmd/shelly-watcher"

// settingsView ist das, was die Einstellungsseite anzeigt. Passwörter werden
// nie ausgeliefert, nur woher sie stammen.
type settingsView struct {
	Values     settingsValues `json:"values"`
	Start      settingsValues `json:"start"`           // Startwerte (Umgebung/Standard)
	Overridden []string       `json:"overridden"`      // in der Oberfläche geänderte Felder
	ShellyPW   string         `json:"shelly_password"` // none | env | settings
	WebPW      string         `json:"web_password"`
	AutoNets   []string       `json:"auto_networks"`
	Persistent bool           `json:"persistent"`
}

type settingsValues struct {
	ScanCIDRs     string `json:"scan_cidrs"`
	ScanMinutes   int    `json:"scan_minutes"`
	PollSeconds   int    `json:"poll_seconds"`
	SleepyHours   int    `json:"sleepy_hours"`
	MDNS          bool   `json:"mdns"`
	CoIoT         bool   `json:"coiot"`
	FWCheckOnline bool   `json:"fw_check_online"`
	AutoUpdate    bool   `json:"auto_update"`
	AutoFrom      int    `json:"auto_update_from"`
	AutoTo        int    `json:"auto_update_to"`
	WifiGood      int    `json:"wifi_good"`
	WifiOK        int    `json:"wifi_ok"`
	ShellyUser    string `json:"shelly_user"`
	WebUser       string `json:"web_user"`
	Debug         bool   `json:"debug"`
}

func valuesOf(c *Config) settingsValues {
	return settingsValues{
		ScanCIDRs: c.ScanCIDRsRaw, ScanMinutes: int(c.ScanInterval / time.Minute),
		PollSeconds: int(c.PollInterval / time.Second), SleepyHours: int(c.SleepyOfflineAfter / time.Hour),
		MDNS: c.MDNS, CoIoT: c.CoIoT, FWCheckOnline: c.FWCheckOnline, WifiGood: c.WifiGood, WifiOK: c.WifiOK,
		AutoUpdate: c.AutoUpdate, AutoFrom: c.AutoUpdateFrom, AutoTo: c.AutoUpdateTo,
		ShellyUser: c.ShellyUser, WebUser: c.WebUser, Debug: c.Debug,
	}
}

func pwSource(override *string, env string) string {
	switch {
	case override != nil && *override != "":
		return "settings"
	case override != nil:
		return "none" // in der Oberfläche bewusst entfernt
	case env != "":
		return "env"
	}
	return "none"
}

func (w *Web) settingsGet(rw http.ResponseWriter, _ *http.Request) {
	ov := w.cfg.Overrides()
	c := w.cfg.Get()
	v := settingsView{
		Values: valuesOf(c), Start: valuesOf(w.cfg.base),
		ShellyPW:   pwSource(ov.ShellyPassword, w.cfg.base.ShellyPassword),
		WebPW:      pwSource(ov.WebPasswordHash, w.cfg.base.WebPassword),
		Persistent: w.cfg.path != "",
	}
	for k, set := range map[string]bool{
		"scan_cidrs": ov.ScanCIDRs != nil, "scan_minutes": ov.ScanInterval != nil, "poll_seconds": ov.PollInterval != nil,
		"sleepy_hours": ov.SleepyOfflineAfter != nil, "mdns": ov.MDNS != nil, "coiot": ov.CoIoT != nil,
		"fw_check_online": ov.FWCheckOnline != nil, "wifi_good": ov.WifiGood != nil, "wifi_ok": ov.WifiOK != nil,
		"shelly_user": ov.ShellyUser != nil, "web_user": ov.WebUser != nil, "debug": ov.Debug != nil,
		"auto_update": ov.AutoUpdate != nil, "auto_update_from": ov.AutoUpdateFrom != nil, "auto_update_to": ov.AutoUpdateTo != nil,
	} {
		if set {
			v.Overridden = append(v.Overridden, k)
		}
	}
	for _, li := range lanInterfaces(c) {
		v.AutoNets = append(v.AutoNets, li.prefix.String())
	}
	writeJSON(rw, v)
}

// settingsPut übernimmt Änderungen. "values" enthält geänderte Felder; ein
// Feld mit null setzt es auf den Startwert zurück. Passwörter: *_password
// setzt (leer = ohne Passwort), *_password_reset=true stellt den Startwert her.
func (w *Web) settingsPut(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Values            map[string]json.RawMessage `json:"values"`
		ShellyPassword    *string                    `json:"shelly_password"`
		ShellyPasswordRst bool                       `json:"shelly_password_reset"`
		WebPassword       *string                    `json:"web_password"`
		WebPasswordRst    bool                       `json:"web_password_reset"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(rw, "ungültige Anfrage", http.StatusBadRequest)
		return
	}
	ov := w.cfg.Overrides()
	for k, raw := range req.Values {
		if err := applySetting(&ov, k, raw); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
	}
	switch {
	case req.ShellyPasswordRst:
		ov.ShellyPassword = nil
	case req.ShellyPassword != nil:
		ov.ShellyPassword = req.ShellyPassword
	}
	switch {
	case req.WebPasswordRst:
		ov.WebPasswordHash = nil
	case req.WebPassword != nil && *req.WebPassword == "":
		empty := ""
		ov.WebPasswordHash = &empty // Schutz aus (auch wenn WEB_PASSWORD gesetzt ist)
	case req.WebPassword != nil:
		h := hashPassword(*req.WebPassword)
		ov.WebPasswordHash = &h
	}
	if err := w.cfg.set(ov, true); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	w.settingsGet(rw, r)
}

func applySetting(ov *Overrides, key string, raw json.RawMessage) error {
	reset := string(raw) == "null"
	str := func(dst **string) error {
		if reset {
			*dst = nil
			return nil
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return errors.New(key + ": Text erwartet")
		}
		s = strings.TrimSpace(s)
		*dst = &s
		return nil
	}
	num := func() (int, error) {
		var n int
		if json.Unmarshal(raw, &n) != nil {
			return 0, errors.New(key + ": Zahl erwartet")
		}
		return n, nil
	}
	dur := func(dst **string, unit time.Duration) error {
		if reset {
			*dst = nil
			return nil
		}
		n, err := num()
		if err != nil {
			return err
		}
		s := (time.Duration(n) * unit).String()
		*dst = &s
		return nil
	}
	boolean := func(dst **bool) error {
		if reset {
			*dst = nil
			return nil
		}
		var b bool
		if json.Unmarshal(raw, &b) != nil {
			return errors.New(key + ": ja/nein erwartet")
		}
		*dst = &b
		return nil
	}
	integer := func(dst **int) error {
		if reset {
			*dst = nil
			return nil
		}
		n, err := num()
		*dst = &n
		return err
	}
	switch key {
	case "scan_cidrs":
		return str(&ov.ScanCIDRs)
	case "scan_minutes":
		return dur(&ov.ScanInterval, time.Minute)
	case "poll_seconds":
		return dur(&ov.PollInterval, time.Second)
	case "sleepy_hours":
		return dur(&ov.SleepyOfflineAfter, time.Hour)
	case "mdns":
		return boolean(&ov.MDNS)
	case "coiot":
		return boolean(&ov.CoIoT)
	case "fw_check_online":
		return boolean(&ov.FWCheckOnline)
	case "debug":
		return boolean(&ov.Debug)
	case "auto_update":
		return boolean(&ov.AutoUpdate)
	case "auto_update_from":
		return integer(&ov.AutoUpdateFrom)
	case "auto_update_to":
		return integer(&ov.AutoUpdateTo)
	case "wifi_good":
		return integer(&ov.WifiGood)
	case "wifi_ok":
		return integer(&ov.WifiOK)
	case "shelly_user":
		return str(&ov.ShellyUser)
	case "web_user":
		return str(&ov.WebUser)
	}
	return errors.New("unbekannte Einstellung: " + key)
}

// info: Daten für die Info-Seite.
func (w *Web) info(rw http.ResponseWriter, _ *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	devs := w.st.list()
	writeJSON(rw, map[string]any{
		"version":    version,
		"repo":       repoURL,
		"go":         runtime.Version(),
		"platform":   runtime.GOOS + "/" + runtime.GOARCH,
		"started":    startedAt,
		"uptime_s":   int64(time.Since(startedAt).Seconds()),
		"rss_bytes":  rssBytes(),
		"heap_bytes": ms.HeapAlloc,
		"devices":    len(devs),
		"models":     len(knownModels),
	})
}

// rssBytes liest den tatsächlichen Speicherverbrauch (Linux), sonst 0.
func rssBytes() int64 {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "VmRSS:"); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 10, 64)
			return n * 1024
		}
	}
	return 0
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(rw).Encode(v)
}

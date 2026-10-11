package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Runtime hält die aktuell gültige Konfiguration. Startwerte kommen aus den
// Umgebungsvariablen; Änderungen aus der Einstellungsseite werden in
// DATA_DIR/settings.json gespeichert, haben Vorrang und gelten sofort, ohne
// Neustart. Alle Teile lesen die Konfiguration bei jeder Verwendung über Get().
type Runtime struct {
	cur  atomic.Pointer[Config]
	base *Config // nur Umgebungsvariablen/Standardwerte
	path string

	mu      sync.Mutex
	ov      Overrides
	changed chan struct{} // wird bei jeder Änderung geschlossen und ersetzt
}

// Overrides sind die in der Oberfläche geänderten Werte. nil = Startwert.
type Overrides struct {
	ScanCIDRs          *string `json:"scan_cidrs,omitempty"`
	ScanInterval       *string `json:"scan_interval,omitempty"`
	PollInterval       *string `json:"poll_interval,omitempty"`
	SleepyOfflineAfter *string `json:"sleepy_offline_after,omitempty"`
	MDNS               *bool   `json:"mdns,omitempty"`
	CoIoT              *bool   `json:"coiot,omitempty"`
	FWCheckOnline      *bool   `json:"fw_check_online,omitempty"`
	WifiGood           *int    `json:"wifi_good,omitempty"`
	WifiOK             *int    `json:"wifi_ok,omitempty"`
	ShellyUser         *string `json:"shelly_user,omitempty"`
	ShellyPassword     *string `json:"shelly_password,omitempty"`
	WebUser            *string `json:"web_user,omitempty"`
	WebPasswordHash    *string `json:"web_password_hash,omitempty"`
	Debug              *bool   `json:"debug,omitempty"`
}

func newRuntime(base *Config, dataDir string) *Runtime {
	r := &Runtime{base: base, changed: make(chan struct{})}
	if dataDir != "" {
		r.path = filepath.Join(dataDir, "settings.json")
	}
	r.cur.Store(base)
	debug.Store(base.Debug)
	return r
}

func (r *Runtime) Get() *Config { return r.cur.Load() }

// Changed liefert einen Kanal, der bei der nächsten Änderung geschlossen wird.
func (r *Runtime) Changed() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changed
}

func (r *Runtime) Overrides() Overrides {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ov
}

// load liest settings.json. reset=true verwirft sie (Notausgang, falls man
// sich mit einem vergessenen Web-Passwort ausgesperrt hat).
func (r *Runtime) load(reset bool) {
	if r.path == "" {
		return
	}
	if reset {
		if err := os.Remove(r.path); err == nil {
			log.Printf("SETTINGS_RESET: Einstellungen aus der Oberfläche verworfen, es gelten die Umgebungsvariablen")
		}
		return
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Einstellungen nicht lesbar: %v", err)
		}
		return
	}
	var ov Overrides
	if err := json.Unmarshal(b, &ov); err != nil {
		log.Printf("settings.json defekt, wird ignoriert: %v", err)
		return
	}
	if err := r.set(ov, false); err != nil {
		log.Printf("settings.json ungültig, wird ignoriert: %v", err)
	}
}

// set prüft die Overrides, übernimmt sie und speichert sie (persist).
func (r *Runtime) set(ov Overrides, persist bool) error {
	c, err := r.build(ov)
	if err != nil {
		return err
	}
	if persist && r.path != "" {
		b, _ := json.MarshalIndent(ov, "", "  ")
		tmp := r.path + ".tmp"
		// 0600: enthält das Shelly-Passwort im Klartext (wird zum Anmelden gebraucht)
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return fmt.Errorf("Speichern fehlgeschlagen: %w", err)
		}
		if err := os.Rename(tmp, r.path); err != nil {
			return fmt.Errorf("Speichern fehlgeschlagen: %w", err)
		}
	}
	r.mu.Lock()
	r.ov = ov
	r.cur.Store(c)
	close(r.changed)
	r.changed = make(chan struct{})
	r.mu.Unlock()
	debug.Store(c.Debug)
	return nil
}

func (r *Runtime) build(ov Overrides) (*Config, error) {
	c := *r.base
	c.ScanCIDRs = slices.Clone(r.base.ScanCIDRs)
	dur := func(dst *time.Duration, v *string, name string) error {
		if v == nil {
			return nil
		}
		d, err := time.ParseDuration(*v)
		if err != nil {
			return fmt.Errorf("%s: ungültige Dauer %q", name, *v)
		}
		*dst = d
		return nil
	}
	if ov.ScanCIDRs != nil {
		p, err := parseCIDRs(*ov.ScanCIDRs)
		if err != nil {
			return nil, fmt.Errorf("Netze: %w", err)
		}
		c.ScanCIDRs, c.ScanCIDRsRaw = p, *ov.ScanCIDRs
	}
	for _, e := range []error{
		dur(&c.ScanInterval, ov.ScanInterval, "Scan-Intervall"),
		dur(&c.PollInterval, ov.PollInterval, "Abfrage-Intervall"),
		dur(&c.SleepyOfflineAfter, ov.SleepyOfflineAfter, "Offline-Grenze Akkugeräte"),
	} {
		if e != nil {
			return nil, e
		}
	}
	if !c.offlineFromEnv {
		c.OfflineAfter = 3*c.PollInterval + 30*time.Second
	}
	setB := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	setB(&c.MDNS, ov.MDNS)
	setB(&c.CoIoT, ov.CoIoT)
	setB(&c.FWCheckOnline, ov.FWCheckOnline)
	setB(&c.Debug, ov.Debug)
	if ov.WifiGood != nil {
		c.WifiGood = *ov.WifiGood
	}
	if ov.WifiOK != nil {
		c.WifiOK = *ov.WifiOK
	}
	if ov.ShellyUser != nil {
		c.ShellyUser = *ov.ShellyUser
	}
	if ov.ShellyPassword != nil {
		c.ShellyPassword = *ov.ShellyPassword
	}
	if ov.WebUser != nil {
		c.WebUser = *ov.WebUser
	}
	if ov.WebPasswordHash != nil {
		c.WebPasswordHash = *ov.WebPasswordHash
		if c.WebPasswordHash == "" {
			c.WebPassword = "" // in der Oberfläche bewusst ohne Passwort
		}
	}
	if strings.TrimSpace(c.WebUser) == "" {
		return nil, errors.New("Benutzername der Oberfläche darf nicht leer sein")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ---- Web-Passwort ----

const pbkdf2Iter = 100_000

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	return "pbkdf2-sha256$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
}

func checkPasswordHash(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 3 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[1])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// webAuthEnabled: Oberfläche ist passwortgeschützt (Umgebung oder Einstellungen).
func (c *Config) webAuthEnabled() bool { return c.WebPasswordHash != "" || c.WebPassword != "" }

func (c *Config) checkWebLogin(user, pw string) bool {
	if subtle.ConstantTimeCompare([]byte(user), []byte(c.WebUser)) != 1 {
		return false
	}
	if c.WebPasswordHash != "" {
		return checkPasswordHash(c.WebPasswordHash, pw)
	}
	return subtle.ConstantTimeCompare([]byte(pw), []byte(c.WebPassword)) == 1
}

// ---- Ausführliches Log, zur Laufzeit umschaltbar ----

var debug atomic.Bool

func debugf(format string, args ...any) {
	if debug.Load() {
		log.Printf("DEBUG "+format, args...)
	}
}

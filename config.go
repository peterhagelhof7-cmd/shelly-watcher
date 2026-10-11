package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen             string
	DataDir            string
	ScanCIDRs          []netip.Prefix
	ScanInterval       time.Duration
	ScanConcurrency    int
	PollInterval       time.Duration
	HTTPTimeout        time.Duration
	MDNS               bool
	MDNSInterval       time.Duration
	CoIoT              bool
	FWCheckOnline      bool
	ShellyUser         string
	ShellyPassword     string
	WebUser            string
	WebPassword        string
	OfflineAfter       time.Duration
	SleepyOfflineAfter time.Duration
	SkipIfaces         []string
	Debug              bool
	AutoUpdate         bool   // Firmware automatisch aktualisieren
	AutoUpdateFrom     int    // Zeitfenster, Stunde von (inkl.)
	AutoUpdateTo       int    // Zeitfenster, Stunde bis (exkl.)
	WifiGood           int    // RSSI ab dem das WLAN "gut" ist
	WifiOK             int    // RSSI ab dem das WLAN "ausreichend" ist
	ScanCIDRsRaw       string // wie eingegeben, für die Einstellungsseite
	WebPasswordHash    string // aus der Einstellungsseite (PBKDF2), hat Vorrang vor WebPassword
	offlineFromEnv     bool
}

func loadConfig() *Config {
	c := &Config{
		Listen:             env("LISTEN", ":8080"),
		DataDir:            env("DATA_DIR", "/data"),
		ScanInterval:       envDur("SCAN_INTERVAL", 15*time.Minute),
		ScanConcurrency:    envInt("SCAN_CONCURRENCY", 32),
		PollInterval:       envDur("POLL_INTERVAL", time.Minute),
		HTTPTimeout:        envDur("HTTP_TIMEOUT", 4*time.Second),
		MDNS:               envBool("MDNS", true),
		MDNSInterval:       envDur("MDNS_INTERVAL", 5*time.Minute),
		CoIoT:              envBool("COIOT", true),
		FWCheckOnline:      envBool("FW_CHECK_ONLINE", true),
		ShellyUser:         env("SHELLY_USER", "admin"),
		ShellyPassword:     envSecret("SHELLY_PASSWORD"),
		WebUser:            env("WEB_USER", "admin"),
		WebPassword:        envSecret("WEB_PASSWORD"),
		SleepyOfflineAfter: envDur("SLEEPY_OFFLINE_AFTER", 26*time.Hour),
		SkipIfaces:         strings.Split(env("SKIP_IFACES", "docker,br-,veth,virbr,vEthernet,lxc,cni,flannel,tun,tap,wg,zt"), ","),
		Debug:              envBool("DEBUG", false),
		AutoUpdate:         envBool("AUTO_UPDATE", false),
		AutoUpdateFrom:     envInt("AUTO_UPDATE_FROM", 3),
		AutoUpdateTo:       envInt("AUTO_UPDATE_TO", 5),
		WifiGood:           envInt("WIFI_GOOD", -67),
		WifiOK:             envInt("WIFI_OK", -79),
		ScanCIDRsRaw:       os.Getenv("SCAN_CIDRS"),
		offlineFromEnv:     os.Getenv("OFFLINE_AFTER") != "",
	}
	c.OfflineAfter = envDur("OFFLINE_AFTER", 3*c.PollInterval+30*time.Second)
	var err error
	if c.ScanCIDRs, err = parseCIDRs(c.ScanCIDRsRaw); err != nil {
		log.Fatalf("SCAN_CIDRS: %v", err)
	}
	if err := c.validate(); err != nil {
		log.Fatal(err)
	}
	if c.ScanConcurrency < 1 {
		c.ScanConcurrency = 1
	}
	return c
}

// parseCIDRs liest "192.168.1.0/24, 10.0.0.5" (Komma, Leerzeichen oder Semikolon).
func parseCIDRs(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' }) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			a, err2 := netip.ParseAddr(f) // einzelne IP erlaubt
			if err2 != nil {
				return nil, fmt.Errorf("%q ist kein gültiges Netz", f)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("%q: nur IPv4 wird unterstützt", f)
		}
		if p.Bits() < 16 {
			return nil, fmt.Errorf("%q ist größer als /16 - bitte kleiner wählen", f)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// validate prüft Werte, die auch über die Einstellungsseite kommen können.
func (c *Config) validate() error {
	switch {
	case c.ScanInterval < time.Minute:
		return errors.New("Scan-Intervall muss mindestens 1 Minute sein")
	case c.PollInterval < 10*time.Second:
		return errors.New("Abfrage-Intervall muss mindestens 10 Sekunden sein")
	case c.SleepyOfflineAfter < time.Hour:
		return errors.New("Offline-Grenze für Akkugeräte muss mindestens 1 Stunde sein")
	case c.AutoUpdateFrom < 0 || c.AutoUpdateFrom > 23 || c.AutoUpdateTo < 0 || c.AutoUpdateTo > 23:
		return errors.New("Update-Zeitfenster: Stunden von 0 bis 23")
	case c.WifiGood > -20 || c.WifiOK < -100 || c.WifiOK >= c.WifiGood:
		return errors.New("WLAN-Grenzen: es muss gelten -100 ≤ ausreichend < gut ≤ -20 dBm")
	}
	return nil
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// envSecret liest KEY oder - Docker-Secrets-Stil - den Inhalt von KEY_FILE.
func envSecret(k string) string {
	if f := os.Getenv(k + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("%s_FILE: %v", k, err)
		}
		return strings.TrimSpace(string(b))
	}
	return os.Getenv(k)
}

func envDur(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Fatalf("%s: ungültige Dauer %q (Beispiele: 30s, 5m, 1h)", k, v)
	}
	return d
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("%s: ungültige Zahl %q", k, v)
	}
	return n
}

func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Fatalf("%s: ungültiger Wahrheitswert %q (true/false)", k, v)
	}
	return b
}

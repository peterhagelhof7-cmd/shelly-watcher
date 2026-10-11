package main

import (
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
	}
	c.OfflineAfter = envDur("OFFLINE_AFTER", 3*c.PollInterval+30*time.Second)
	for _, f := range strings.FieldsFunc(os.Getenv("SCAN_CIDRS"), func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			// einzelne IP erlaubt
			if a, err2 := netip.ParseAddr(f); err2 == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				log.Fatalf("SCAN_CIDRS: %q ist kein gültiges Netz: %v", f, err)
			}
		}
		if !p.Addr().Is4() {
			log.Fatalf("SCAN_CIDRS: %q - nur IPv4 wird unterstützt", f)
		}
		if p.Bits() < 16 {
			log.Fatalf("SCAN_CIDRS: %q ist größer als /16 - bitte kleiner wählen", f)
		}
		c.ScanCIDRs = append(c.ScanCIDRs, p.Masked())
	}
	if c.ScanConcurrency < 1 {
		c.ScanConcurrency = 1
	}
	return c
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

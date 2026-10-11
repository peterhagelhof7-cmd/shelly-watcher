// shelly-watcher findet alle Shelly-Geräte im Netz (Gen1 bis Gen4, Pro,
// Wall Display ...) und zeigt Modell, Firmware und Update-Stand zentral an.
package main

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	version = "dev" // per -ldflags gesetzt
	debug   bool
)

func webSub() fs.FS {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	return sub
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		// Für HEALTHCHECK im scratch-Image (dort gibt es kein curl/wget).
		os.Exit(healthcheck())
	}
	log.SetFlags(log.Ldate | log.Ltime)
	cfg := loadConfig()
	debug = cfg.Debug
	log.Printf("shelly-watcher %s startet, Web auf %s", version, cfg.Listen)

	if cfg.DataDir != "" {
		if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
			log.Printf("DATA_DIR %s nicht nutzbar, keine Persistenz: %v", cfg.DataDir, err)
			cfg.DataDir = ""
		}
	}
	st := newStore(cfg)
	st.load()
	ref := &FWRef{}
	st.ref = ref
	pr := newProber(cfg, st)
	sc := newScanner(cfg, pr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(cfg.ScanCIDRs) == 0 {
		for _, li := range lanInterfaces(cfg) {
			log.Printf("Netz erkannt: %s %s", li.ifi.Name, li.prefix)
		}
	}
	go pr.run(ctx)
	go sc.run(ctx)
	go runPoller(ctx, cfg, st, pr)
	if cfg.MDNS {
		go runMDNS(ctx, cfg, pr)
	}
	if cfg.FWCheckOnline {
		go runFWRef(ctx, ref)
	}
	if cfg.CoIoT {
		go runCoIoT(ctx, cfg, pr, st)
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st.save()
			}
		}
	}()

	web := &Web{cfg: cfg, st: st, pr: pr, sc: sc, ref: ref}
	srv := &http.Server{Addr: cfg.Listen, Handler: web.handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Webserver: %v", err)
	}
	st.save()
	log.Printf("beendet")
}

// runPoller fragt bekannte (nicht schlafende) Geräte regelmäßig ab, damit
// Online-Status, Firmware und Update-Hinweise aktuell bleiben.
func runPoller(ctx context.Context, cfg *Config, st *Store, pr *Prober) {
	t := time.NewTicker(cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, ip := range st.pollTargets() {
				pr.enqueue(ip, "poll", false)
			}
		}
	}
}

func healthcheck() int {
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	if addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

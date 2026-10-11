package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Erkennung veralteter Firmware. Die neueste bekannte stabile Version eines
// Geräts ist das Maximum aus drei Quellen:
//
//   - "gerät":  das Gerät meldet selbst ein Update (braucht Internet am Shelly)
//   - "shelly": offizielle Gen1-Liste api.shelly.cloud/files/firmware
//     (für Gen2+ veröffentlicht Shelly keine solche Liste)
//   - "netz":   ein anderes Gerät desselben Modells im Netz hat eine neuere
//     Version (funktioniert komplett offline, auch für Gen2+)

const gen1FirmwareURL = "https://api.shelly.cloud/files/firmware"

type FWRef struct {
	mu      sync.Mutex
	gen1    map[string]string // Typcode -> Version
	fetched time.Time
	err     string
}

func (r *FWRef) latestGen1(model string) string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gen1[model]
}

func (r *FWRef) info() (time.Time, string) {
	if r == nil {
		return time.Time{}, ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fetched, r.err
}

// runFWRef lädt die Gen1-Liste täglich (bei Fehler stündlich), solange
// FW_CHECK_ONLINE an ist. Abschalten verwirft die Liste sofort, Einschalten
// lädt sofort; andere Einstellungsänderungen lassen den Zeitplan unberührt.
func runFWRef(ctx context.Context, r *FWRef, rt *Runtime) {
	var next time.Time // nächster Ladezeitpunkt; null = sofort
	for {
		changed := rt.Changed()
		if !rt.Get().FWCheckOnline {
			r.mu.Lock()
			r.gen1, r.fetched, r.err = nil, time.Time{}, ""
			r.mu.Unlock()
			next = time.Time{}
			select {
			case <-ctx.Done():
				return
			case <-changed:
				continue
			}
		}
		if !time.Now().Before(next) {
			next = time.Now().Add(24 * time.Hour)
			if err := r.fetch(ctx); err != nil {
				log.Printf("Firmware-Liste (Gen1) nicht abrufbar, erneuter Versuch in 1 h: %v", err)
				r.mu.Lock()
				r.err = err.Error()
				r.mu.Unlock()
				next = time.Now().Add(time.Hour)
			}
		}
		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-changed:
			t.Stop()
		}
	}
}

func (r *FWRef) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, gen1FirmwareURL, nil)
	req.Header.Set("User-Agent", "shelly-watcher/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErr(resp.StatusCode)
	}
	var body struct {
		IsOK bool `json:"isok"`
		Data map[string]struct {
			Version string `json:"version"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return err
	}
	m := make(map[string]string, len(body.Data))
	for model, e := range body.Data {
		if v := gen1Version(e.Version); v != "" {
			m[model] = v
		}
	}
	if len(m) == 0 {
		return io.ErrUnexpectedEOF
	}
	r.mu.Lock()
	r.gen1, r.fetched, r.err = m, time.Now(), ""
	r.mu.Unlock()
	log.Printf("Firmware-Liste (Gen1): %d Modelle", len(m))
	return nil
}

// assessFirmware setzt FWLatest/FWLatestSrc/Outdated für alle Geräte.
func assessFirmware(devs []Device, ref *FWRef) {
	netMax := map[string]string{}
	for _, d := range devs {
		if d.Model != "" && d.FWVersion != "" && !isPrerelease(d.FWVersion) &&
			cmpVersion(d.FWVersion, netMax[d.Model]) > 0 {
			netMax[d.Model] = d.FWVersion
		}
	}
	for i := range devs {
		d := &devs[i]
		if d.FWVersion == "" {
			continue
		}
		consider := func(v, src string) {
			if v != "" && !isPrerelease(v) && cmpVersion(v, d.FWLatest) > 0 {
				d.FWLatest, d.FWLatestSrc = v, src
			}
		}
		consider(d.FWStable, "gerät")
		if d.Gen == 1 {
			consider(ref.latestGen1(d.Model), "shelly")
		}
		consider(netMax[d.Model], "netz")
		d.Outdated = d.FWLatest != "" && cmpVersion(d.FWVersion, d.FWLatest) < 0
		if !d.Outdated {
			d.FWLatest, d.FWLatestSrc = "", ""
		}
	}
}

func isPrerelease(v string) bool {
	_, pre, _ := strings.Cut(v, "-")
	return pre != ""
}

// cmpVersion vergleicht "1.14.0", "1.4.4", "1.5.0-beta1" numerisch;
// eine Vorabversion ist älter als die zugehörige Release-Version.
// Leer ist älter als alles.
func cmpVersion(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	an, apre, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	bn, bpre, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")
	ap, bp := strings.Split(an, "."), strings.Split(bn, ".")
	for i := 0; i < max(len(ap), len(bp)); i++ {
		var x, y int
		if i < len(ap) {
			x, _ = strconv.Atoi(ap[i])
		}
		if i < len(bp) {
			y, _ = strconv.Atoi(bp[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	case apre < bpre:
		return -1
	default:
		return 1
	}
}

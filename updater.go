package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// Automatische Firmware-Updates. Bewusst vorsichtig:
//   - nur wenn in den Einstellungen aktiviert, nur im Zeitfenster
//   - nur stabile Firmware, die das Gerät selbst als verfügbar meldet
//     (das Gerät lädt sie vom Shelly-Server, braucht also Internet)
//   - ein Gerät nach dem anderen; erst wenn es mit neuer Version zurück ist,
//     kommt das nächste
//   - Geräte mit Ausnahme, schlafende Akkugeräte und Geräte ohne gültiges
//     Passwort werden ausgelassen; nach einem Fehlschlag 24 h Pause je Gerät

// UpdateInfo ist das Ergebnis des letzten Update-Versuchs eines Geräts.
type UpdateInfo struct {
	At     time.Time `json:"at"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	State  string    `json:"state"` // running | ok | failed
	Detail string    `json:"detail,omitempty"`
	Manual bool      `json:"manual,omitempty"`
}

type Updater struct {
	cfg *Runtime
	st  *Store
	pr  *Prober

	mu      sync.Mutex
	busy    bool
	trigger chan struct{}

	// für Tests verkürzbar
	pollEvery   time.Duration
	giveUpAfter time.Duration
	retryAfter  time.Duration
	now         func() time.Time
}

func newUpdater(cfg *Runtime, st *Store, pr *Prober) *Updater {
	return &Updater{
		cfg: cfg, st: st, pr: pr, trigger: make(chan struct{}, 1),
		pollEvery: 15 * time.Second, giveUpAfter: 10 * time.Minute, retryAfter: 24 * time.Hour,
		now: time.Now,
	}
}

// inWindow: Stunde h liegt im Fenster [from, to). from == to heißt ganztägig;
// Fenster über Mitternacht (z.B. 22–4) sind erlaubt.
func inWindow(h, from, to int) bool {
	switch {
	case from == to:
		return true
	case from < to:
		return h >= from && h < to
	default:
		return h >= from || h < to
	}
}

func (u *Updater) run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-u.trigger:
		}
		c := u.cfg.Get()
		if !c.AutoUpdate || !inWindow(u.now().Hour(), c.AutoUpdateFrom, c.AutoUpdateTo) {
			continue
		}
		if d, ok := u.nextCandidate(); ok {
			_ = u.update(ctx, d, false)
		}
	}
}

// eligible prüft, ob ein Gerät automatisch aktualisiert werden darf.
func (u *Updater) eligible(d *Device) bool {
	if d.Status != "online" || d.Sleepy || d.AutoUpdateOff || d.IP == "" || d.FWStable == "" {
		return false
	}
	if d.AuthStatus != "ok" && d.AuthStatus != "none" {
		return false
	}
	if cmpVersion(d.FWStable, d.FWVersion) <= 0 || isPrerelease(d.FWStable) {
		return false
	}
	if l := d.LastUpdate; l != nil && l.State == "failed" && u.now().Sub(l.At) < u.retryAfter {
		return false
	}
	return true
}

func (u *Updater) nextCandidate() (Device, bool) {
	for _, d := range u.st.list() {
		if u.eligible(&d) {
			return d, true
		}
	}
	return Device{}, false
}

var errBusy = errors.New("es läuft bereits ein Update")

// update stößt das Update an und wartet, bis das Gerät mit neuer Version
// zurück ist. Läuft immer nur einmal gleichzeitig.
func (u *Updater) update(ctx context.Context, d Device, manual bool) error {
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		return errBusy
	}
	u.busy = true
	u.mu.Unlock()
	defer func() { u.mu.Lock(); u.busy = false; u.mu.Unlock() }()

	info := UpdateInfo{At: u.now(), From: d.FWVersion, To: d.FWStable, State: "running", Manual: manual}
	u.st.setUpdate(d.MAC, info)
	log.Printf("Firmware-Update %s (%s, %s): %s -> %s gestartet", d.MAC, d.ModelName, d.IP, d.FWVersion, d.FWStable)

	if err := u.pr.startUpdate(ctx, d.IP, d.Gen); err != nil {
		info.State, info.Detail = "failed", "Update konnte nicht gestartet werden: "+err.Error()
		u.st.setUpdate(d.MAC, info)
		log.Printf("Firmware-Update %s: %s", d.MAC, info.Detail)
		return err
	}

	deadline := u.now().Add(u.giveUpAfter)
	for u.now().Before(deadline) {
		select {
		case <-ctx.Done():
			info.State, info.Detail = "failed", "abgebrochen (Watcher beendet)"
			u.st.setUpdate(d.MAC, info)
			return ctx.Err()
		case <-time.After(u.pollEvery):
		}
		obs, err := u.pr.probe(ctx, d.IP)
		if err != nil || normMAC(obs.MAC) != d.MAC {
			continue // startet gerade neu
		}
		if cmpVersion(obs.FWVersion, d.FWVersion) > 0 {
			u.st.apply(obs, "poll")
			info.State, info.Detail, info.To = "ok", "", obs.FWVersion
			u.st.setUpdate(d.MAC, info)
			log.Printf("Firmware-Update %s: erfolgreich, jetzt %s", d.MAC, obs.FWVersion)
			return nil
		}
	}
	info.State = "failed"
	info.Detail = fmt.Sprintf("nach %s noch alte Version - hat das Gerät Internetzugang?", u.giveUpAfter)
	u.st.setUpdate(d.MAC, info)
	log.Printf("Firmware-Update %s: %s", d.MAC, info.Detail)
	return errors.New(info.Detail)
}

// startUpdate löst beim Gerät die Installation der neuesten stabilen
// Firmware aus. Das Gerät lädt sie selbst vom Shelly-Server.
func (p *Prober) startUpdate(ctx context.Context, ip string, gen int) error {
	var resp json.RawMessage
	if gen >= 2 {
		return p.get(ctx, ip, `/rpc/Shelly.Update?stage=%22stable%22`, authDigest, &resp)
	}
	return p.get(ctx, ip, "/ota?update=true", authBasic, &resp)
}

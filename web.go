package main

import (
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

type Web struct {
	cfg *Runtime
	st  *Store
	pr  *Prober
	sc  *Scanner
	ref *FWRef
	up  *Updater
	ctx context.Context // lebt so lange wie der Watcher (für Updates im Hintergrund)
}

func (w *Web) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(webSub()))
	mux.HandleFunc("GET /api/devices", w.devices)
	mux.HandleFunc("GET /api/devices.csv", w.devicesCSV)
	mux.HandleFunc("POST /api/scan", w.scan)
	mux.HandleFunc("POST /api/probe", w.probe)
	mux.HandleFunc("GET /api/devices/{mac}", w.device)
	mux.HandleFunc("POST /api/devices/{mac}/update", w.startUpdate)
	mux.HandleFunc("PUT /api/devices/{mac}/autoupdate", w.setAutoUpdate)
	mux.HandleFunc("GET /api/settings", w.settingsGet)
	mux.HandleFunc("PUT /api/settings", w.settingsPut)
	mux.HandleFunc("GET /api/info", w.info)
	mux.HandleFunc("DELETE /api/devices/{mac}", w.forget)
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) { rw.Write([]byte("ok\n")) })
	mux.Handle("GET /ws", w.wsServer())
	return w.auth(mux)
}

// auth: optionaler Passwortschutz der Oberfläche. /ws (Geräte) und /healthz
// (Docker-Healthcheck) bleiben frei.
func (w *Web) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		c := w.cfg.Get() // Passwort kann sich zur Laufzeit ändern
		if !c.webAuthEnabled() || r.URL.Path == "/ws" || r.URL.Path == "/healthz" {
			next.ServeHTTP(rw, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok || !c.checkWebLogin(u, p) {
			rw.Header().Set("WWW-Authenticate", `Basic realm="shelly-watcher"`)
			http.Error(rw, "Anmeldung erforderlich", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

func (w *Web) devices(rw http.ResponseWriter, _ *http.Request) {
	last, nets, running := w.sc.info()
	resp := struct {
		Version   string    `json:"version"`
		Now       time.Time `json:"now"`
		Devices   []Device  `json:"devices"`
		Scanning  bool      `json:"scanning"`
		LastScan  time.Time `json:"last_scan"`
		Networks  []string  `json:"networks"`
		HasPasswd bool      `json:"shelly_password_set"`
		FWListAt  time.Time `json:"fw_list_fetched"`
		FWListErr string    `json:"fw_list_error,omitempty"`
		AutoUpd   bool      `json:"auto_update"`
		WifiGood  int       `json:"wifi_good"`
		WifiOK    int       `json:"wifi_ok"`
	}{Version: version, Now: time.Now(), Devices: w.st.list(), Scanning: running, LastScan: last,
		Networks: nets, HasPasswd: w.cfg.Get().ShellyPassword != "",
		WifiGood: w.cfg.Get().WifiGood, WifiOK: w.cfg.Get().WifiOK, AutoUpd: w.cfg.Get().AutoUpdate}
	resp.FWListAt, resp.FWListErr = w.ref.info()
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(rw).Encode(resp)
}

func (w *Web) devicesCSV(rw http.ResponseWriter, _ *http.Request) {
	rw.Header().Set("Content-Type", "text/csv; charset=utf-8")
	rw.Header().Set("Content-Disposition", `attachment; filename="shelly-geraete.csv"`)
	rw.Write([]byte("\xef\xbb\xbf")) // BOM, damit Excel UTF-8 erkennt
	cw := csv.NewWriter(rw)
	cw.Comma = ';'
	_ = cw.Write([]string{"Status", "Name", "Modell", "Modellcode", "Generation", "Firmware", "Firmware komplett",
		"Veraltet", "Neueste bekannte Version", "Quelle", "Update laut Gerät", "Beta verfügbar", "IP", "MAC", "Geräte-ID", "SSID", "RSSI", "Batterie", "Passwortschutz",
		"Zuerst gesehen", "Zuletzt gesehen", "Fehler"})
	for _, d := range w.st.list() {
		_ = cw.Write([]string{d.Status, d.Name, d.ModelName, d.Model, strconv.Itoa(d.Gen), d.FWVersion, d.FW,
			jaNein(d.Outdated), d.FWLatest, d.FWLatestSrc, d.FWStable, d.FWBeta, d.IP, d.MAC, d.ID, d.SSID, intp(d.RSSI), intp(d.Battery), d.AuthStatus,
			d.FirstSee.Format(time.RFC3339), d.LastSeen.Format(time.RFC3339), d.LastErr})
	}
	cw.Flush()
}

func jaNein(b bool) string {
	if b {
		return "ja"
	}
	return "nein"
}

func intp(p *int) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(*p)
}

func (w *Web) scan(rw http.ResponseWriter, _ *http.Request) {
	for _, ip := range w.st.pollTargets() {
		w.pr.enqueue(ip, "poll", true)
	}
	if !w.sc.requestScan() {
		http.Error(rw, "Scan läuft bereits", http.StatusConflict)
		return
	}
	rw.WriteHeader(http.StatusAccepted)
}

// probe: einzelne IP manuell hinzufügen (z.B. Gerät in anderem VLAN).
func (w *Web) probe(rw http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		http.Error(rw, "ungültige IPv4-Adresse", http.StatusBadRequest)
		return
	}
	d, err := w.pr.probe(r.Context(), a.String())
	if err != nil {
		http.Error(rw, a.String()+": "+err.Error(), http.StatusBadGateway)
		return
	}
	w.st.apply(d, "manuell")
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(d)
}

// device liefert ein Gerät mit Schaltzuständen und Messwerten. Ist es
// erreichbar, wird vorher live abgefragt (inkl. Kanalnamen und Cloud-Server).
func (w *Web) device(rw http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	d, ok := w.st.get(mac)
	if !ok {
		http.NotFound(rw, r)
		return
	}
	liveErr := ""
	if d.IP != "" && d.Status == "online" {
		ctx, cancel := context.WithTimeout(r.Context(), 2*w.cfg.Get().HTTPTimeout)
		obs, err := w.pr.probeFull(ctx, d.IP, true)
		cancel()
		switch {
		case err != nil:
			liveErr = err.Error()
		case normMAC(obs.MAC) != d.MAC:
			liveErr = "unter " + d.IP + " antwortet inzwischen ein anderes Gerät"
		default:
			w.st.apply(obs, "poll")
			d, _ = w.st.get(mac)
		}
	}
	c := w.cfg.Get()
	writeJSON(rw, struct {
		Device
		LiveError string    `json:"live_error,omitempty"`
		Now       time.Time `json:"now"`
		WifiGood  int       `json:"wifi_good"`
		WifiOK    int       `json:"wifi_ok"`
		AutoUpd   bool      `json:"auto_update"`
		AutoFrom  int       `json:"auto_update_from"`
		AutoTo    int       `json:"auto_update_to"`
	}{d, liveErr, time.Now(), c.WifiGood, c.WifiOK, c.AutoUpdate, c.AutoUpdateFrom, c.AutoUpdateTo})
}

// startUpdate: Firmware-Update für ein Gerät sofort auslösen (unabhängig
// vom Zeitfenster und von der Ausnahme). Läuft im Hintergrund.
func (w *Web) startUpdate(rw http.ResponseWriter, r *http.Request) {
	d, ok := w.st.get(r.PathValue("mac"))
	switch {
	case !ok:
		http.NotFound(rw, r)
		return
	case d.Status != "online" || d.IP == "":
		http.Error(rw, "Gerät ist nicht online", http.StatusConflict)
		return
	case d.FWStable == "" || cmpVersion(d.FWStable, d.FWVersion) <= 0:
		http.Error(rw, "Das Gerät meldet kein verfügbares Update", http.StatusConflict)
		return
	case d.AuthStatus == "missing" || d.AuthStatus == "failed":
		http.Error(rw, "Ohne gültiges Shelly-Passwort kein Update möglich", http.StatusConflict)
		return
	}
	w.up.mu.Lock()
	busy := w.up.busy
	w.up.mu.Unlock()
	if busy {
		http.Error(rw, errBusy.Error(), http.StatusConflict)
		return
	}
	ctx := w.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go func() { _ = w.up.update(ctx, d, true) }()
	rw.WriteHeader(http.StatusAccepted)
}

func (w *Web) setAutoUpdate(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if json.NewDecoder(http.MaxBytesReader(rw, r.Body, 1024)).Decode(&req) != nil {
		http.Error(rw, "ungültige Anfrage", http.StatusBadRequest)
		return
	}
	if !w.st.setAutoUpdateOff(r.PathValue("mac"), !req.Enabled) {
		http.NotFound(rw, r)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

func (w *Web) forget(rw http.ResponseWriter, r *http.Request) {
	if !w.st.remove(r.PathValue("mac")) {
		http.NotFound(rw, r)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	errNotShelly = errors.New("kein Shelly")
	errAuth      = errors.New("Anmeldung fehlgeschlagen (SHELLY_PASSWORD prüfen)")
)

type statusErr int

func (e statusErr) Error() string { return fmt.Sprintf("HTTP %d", int(e)) }

type authMode int

const (
	authNone authMode = iota
	authBasic
	authDigest
)

type probeReq struct {
	ip, source string
}

// Prober fragt Geräte per HTTP ab. Alle Quellen (Scan, mDNS, CoIoT, Poll,
// Web) reichen IPs über enqueue ein; eine kleine Worker-Zahl hält RAM und
// Last auf den Geräten gering.
type Prober struct {
	cfg    *Runtime
	st     *Store
	client *http.Client
	queue  chan probeReq

	mu   sync.Mutex
	last map[string]time.Time

	// lost wird aufgerufen, wenn ein bekanntes Gerät unter seiner IP nicht
	// mehr antwortet oder dort plötzlich ein anderes Gerät sitzt (z.B. nach
	// einem DHCP-Wechsel). Darf nil sein.
	lost func(ip string)
}

const (
	probeWorkers = 4
	probeMinGap  = 20 * time.Second
	maxBodyBytes = 1 << 20
)

func newProber(cfg *Runtime, st *Store) *Prober {
	timeout := cfg.Get().HTTPTimeout
	tr := &http.Transport{
		Proxy:                 nil, // LAN-Geräte nie über einen Proxy
		DialContext:           (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		DisableKeepAlives:     true, // Shellys haben wenige Sockets, nicht blockieren
		ResponseHeaderTimeout: timeout,
	}
	return &Prober{
		cfg:    cfg,
		st:     st,
		client: &http.Client{Transport: tr, Timeout: timeout},
		queue:  make(chan probeReq, 256),
		last:   map[string]time.Time{},
	}
}

// enqueue stellt eine IP zur Abfrage ein. Mehrfachmeldungen derselben IP
// innerhalb von probeMinGap werden verworfen, außer force ist gesetzt.
func (p *Prober) enqueue(ip, source string, force bool) {
	now := time.Now()
	p.mu.Lock()
	if t, ok := p.last[ip]; ok && !force && now.Sub(t) < probeMinGap {
		p.mu.Unlock()
		return
	}
	p.last[ip] = now
	if len(p.last) > 4096 {
		for k, t := range p.last {
			if now.Sub(t) > probeMinGap {
				delete(p.last, k)
			}
		}
	}
	p.mu.Unlock()
	select {
	case p.queue <- probeReq{ip, source}:
	default:
		debugf("Probe-Warteschlange voll, %s verworfen", ip)
	}
}

// submit stellt ohne Duplikatsperre ein und wartet notfalls (für den Scan,
// der keine Treffer verlieren soll).
func (p *Prober) submit(ctx context.Context, ip, source string) {
	p.mu.Lock()
	p.last[ip] = time.Now()
	p.mu.Unlock()
	select {
	case p.queue <- probeReq{ip, source}:
	case <-ctx.Done():
	}
}

func (p *Prober) run(ctx context.Context) {
	var wg sync.WaitGroup
	for range probeWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case r := <-p.queue:
					p.handle(ctx, r)
				}
			}
		}()
	}
	wg.Wait()
}

func (p *Prober) handle(ctx context.Context, r probeReq) {
	expect := p.st.macAt(r.ip)
	d, err := p.probe(ctx, r.ip)
	if err != nil {
		if expect == "" {
			if !errors.Is(err, errNotShelly) {
				debugf("%s (%s): %v", r.ip, r.source, err)
			}
			return
		}
		if errors.Is(err, errNotShelly) {
			err = errors.New("unter dieser IP antwortet kein Shelly mehr")
		}
		debugf("%s (%s): %v", r.ip, r.source, err)
		// Nur beim regelmäßigen Poll und nur beim Übergang ok -> Fehler neu
		// suchen: Ausgeschaltete Geräte sollen keinen Dauer-Scan auslösen, und
		// schlafende Akkugeräte (Abfrage nach CoIoT/WS) sind kein Verlust.
		if p.st.failed(r.ip, err) && r.source == "poll" && p.lost != nil {
			p.lost(r.ip)
		}
		return
	}
	if expect != "" && expect != normMAC(d.MAC) && p.lost != nil {
		// Unter der IP sitzt jetzt ein anderes Gerät; das bisherige ist umgezogen.
		p.lost(r.ip)
	}
	p.st.apply(d, r.source)
}

// shellyInfo deckt /shelly von Gen1 und Gen2+ ab (Feldnamen unterscheiden sich).
type shellyInfo struct {
	// Gen1
	Type string `json:"type"`
	FW   string `json:"fw"`
	Auth bool   `json:"auth"`
	// Gen2+
	Gen    int    `json:"gen"`
	ID     string `json:"id"`
	Model  string `json:"model"`
	Ver    string `json:"ver"`
	FWID   string `json:"fw_id"`
	App    string `json:"app"`
	Name   string `json:"name"`
	AuthEn bool   `json:"auth_en"`
	// beide
	MAC string `json:"mac"`
}

func (p *Prober) probe(ctx context.Context, ip string) (*Device, error) {
	return p.probeFull(ctx, ip, false)
}

// probeFull fragt zusätzlich die Konfiguration ab (Kanalnamen, Cloud-Server
// bei Gen2+). Das braucht nur die Detailseite, nicht der minütliche Poll.
func (p *Prober) probeFull(ctx context.Context, ip string, withConfig bool) (*Device, error) {
	var si shellyInfo
	if err := p.get(ctx, ip, "/shelly", authNone, &si); err != nil {
		var se statusErr
		if errors.Is(err, errAuth) || errors.As(err, &se) || isJSONErr(err) {
			return nil, errNotShelly
		}
		return nil, err
	}
	if si.MAC == "" || (si.Type == "" && si.Gen < 2) {
		return nil, errNotShelly
	}
	d := &Device{IP: ip, MAC: normMAC(si.MAC)}
	if si.Gen >= 2 {
		d.applyGen2Info(&si)
		if si.AuthEn && p.cfg.Get().ShellyPassword == "" {
			d.AuthStatus = "missing"
			return d, nil
		}
		var raw json.RawMessage
		if err := p.get(ctx, ip, "/rpc/Shelly.GetStatus", authDigest, &raw); err != nil {
			return p.partial(d, err)
		}
		d.applyGen2Raw(raw)
		if withConfig && d.Detail != nil {
			var cfgRaw json.RawMessage
			if err := p.get(ctx, ip, "/rpc/Shelly.GetConfig", authDigest, &cfgRaw); err == nil {
				names, on, srv := gen2Config(cfgRaw)
				applyNames(d.Detail, names)
				d.Detail.CloudOn, d.Detail.CloudSrv = on, srv
			}
		}
		d.AuthStatus = authOK(si.AuthEn)
		return d, nil
	}

	d.Gen = 1
	d.Model = si.Type
	d.FW = si.FW
	d.FWVersion = gen1Version(si.FW)
	d.AuthEnable = si.Auth
	if si.Auth && p.cfg.Get().ShellyPassword == "" {
		d.AuthStatus = "missing"
		return d, nil
	}
	var setRaw, stRaw json.RawMessage
	if err := p.get(ctx, ip, "/settings", authBasic, &setRaw); err != nil {
		return p.partial(d, err)
	}
	if err := p.get(ctx, ip, "/status", authBasic, &stRaw); err != nil {
		return p.partial(d, err)
	}
	var set gen1Settings
	var st gen1Status
	if json.Unmarshal(setRaw, &set) != nil || json.Unmarshal(stRaw, &st) != nil {
		return p.partial(d, errors.New("ungültige Antwort"))
	}
	d.applyGen1(&set, &st)
	d.Detail = gen1Detail(stRaw, setRaw)
	d.AuthStatus = authOK(si.Auth)
	return d, nil
}

// partial: /shelly war lesbar (Modell + Firmware sind also bekannt), die
// Detailabfrage nicht. Das Gerät wird trotzdem übernommen.
func (p *Prober) partial(d *Device, err error) (*Device, error) {
	if errors.Is(err, errAuth) {
		d.AuthStatus = "failed"
	}
	d.LastErr = err.Error()
	return d, nil
}

func authOK(enabled bool) string {
	if enabled {
		return "ok"
	}
	return "none"
}

func isJSONErr(err error) bool {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	return errors.As(err, &se) || errors.As(err, &te) || errors.Is(err, io.ErrUnexpectedEOF)
}

func (p *Prober) get(ctx context.Context, ip, path string, mode authMode, v any) error {
	url := "http://" + ip + path
	resp, err := p.do(ctx, url, mode, "")
	if err != nil {
		return err
	}
	if pw := p.cfg.Get().ShellyPassword; resp.StatusCode == http.StatusUnauthorized && mode == authDigest && pw != "" {
		ch, ok := findDigest(resp.Header)
		resp.Body.Close()
		if !ok {
			return errAuth
		}
		authz := ch.authorization("admin", pw, http.MethodGet, path, newCnonce(), 1)
		if resp, err = p.do(ctx, url, authNone, authz); err != nil {
			return err
		}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return errAuth
	case resp.StatusCode != http.StatusOK:
		return statusErr(resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(v)
}

func (p *Prober) do(ctx context.Context, url string, mode authMode, authz string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "shelly-watcher/"+version)
	if c := p.cfg.Get(); mode == authBasic && c.ShellyPassword != "" {
		req.SetBasicAuth(c.ShellyUser, c.ShellyPassword)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	return p.client.Do(req)
}

func findDigest(h http.Header) (digestChallenge, bool) {
	for _, v := range h.Values("WWW-Authenticate") {
		if c, ok := parseDigest(v); ok {
			return c, true
		}
	}
	return digestChallenge{}, false
}

// ---- Gen1 ----

type gen1Settings struct {
	Name   string `json:"name"`
	Device struct {
		Hostname string `json:"hostname"`
	} `json:"device"`
}

type gen1Status struct {
	WifiSta *struct {
		SSID string `json:"ssid"`
		RSSI *int   `json:"rssi"`
	} `json:"wifi_sta"`
	Cloud *struct {
		Connected bool `json:"connected"`
	} `json:"cloud"`
	Update *struct {
		HasUpdate   bool   `json:"has_update"`
		NewVersion  string `json:"new_version"`
		OldVersion  string `json:"old_version"`
		BetaVersion string `json:"beta_version"`
	} `json:"update"`
	Uptime int64 `json:"uptime"`
	Bat    *struct {
		Value *int `json:"value"`
	} `json:"bat"`
}

func (d *Device) applyGen1(set *gen1Settings, st *gen1Status) {
	d.Name = set.Name
	d.ID = set.Device.Hostname
	if w := st.WifiSta; w != nil {
		d.SSID, d.RSSI = w.SSID, w.RSSI
	}
	if st.Cloud != nil {
		c := st.Cloud.Connected
		d.Cloud = &c
	}
	if u := st.Update; u != nil {
		if u.HasUpdate {
			d.FWStable = gen1Version(u.NewVersion)
		}
		if b := gen1Version(u.BetaVersion); b != "" && b != d.FWVersion && u.BetaVersion != u.OldVersion {
			d.FWBeta = b
		}
	}
	d.Uptime = st.Uptime
	if st.Bat != nil && st.Bat.Value != nil {
		d.Battery = st.Bat.Value
	}
}

// gen1Version: "20230913-112003/v1.14.0-gcb84623" -> "1.14.0".
func gen1Version(fw string) string {
	if i := strings.LastIndexByte(fw, '/'); i >= 0 {
		fw = fw[i+1:]
	}
	fw = strings.TrimPrefix(fw, "v")
	if i := strings.Index(fw, "-g"); i >= 0 {
		fw = fw[:i]
	}
	if i := strings.IndexByte(fw, '@'); i >= 0 {
		fw = fw[:i]
	}
	return fw
}

// ---- Gen2+ (Gen2, Gen3, Gen4, Pro, Wall Display ...) ----

type gen2Status struct {
	Sys *struct {
		Uptime           int64 `json:"uptime"`
		AvailableUpdates struct {
			Stable *struct{ Version string } `json:"stable"`
			Beta   *struct{ Version string } `json:"beta"`
		} `json:"available_updates"`
	} `json:"sys"`
	Wifi *struct {
		SSID *string `json:"ssid"`
		RSSI *int    `json:"rssi"`
	} `json:"wifi"`
	Cloud *struct {
		Connected bool `json:"connected"`
	} `json:"cloud"`
	Eth *struct {
		IP *string `json:"ip"`
	} `json:"eth"`
	DevPower *struct {
		Battery struct {
			Percent *int `json:"percent"`
		} `json:"battery"`
	} `json:"devicepower:0"`
}

func (d *Device) applyGen2Info(si *shellyInfo) {
	d.MAC = normMAC(si.MAC)
	d.Gen = si.Gen
	d.ID = si.ID
	d.Model = si.Model
	d.App = si.App
	d.Name = si.Name
	d.FW = si.FWID
	d.FWVersion = si.Ver
	d.AuthEnable = si.AuthEn
}

// applyGen2Raw wertet einen kompletten Shelly.GetStatus aus (Poll und WS).
func (d *Device) applyGen2Raw(raw json.RawMessage) {
	var st gen2Status
	if json.Unmarshal(raw, &st) != nil {
		return
	}
	d.applyGen2Status(&st)
	d.Detail = &Detail{Components: gen2Components(raw), At: time.Now()}
	if st.Cloud != nil {
		c := st.Cloud.Connected
		d.Detail.CloudConn = &c
	}
	d.Wired = st.Eth != nil && st.Eth.IP != nil && (st.Wifi == nil || st.Wifi.RSSI == nil)
}

func (d *Device) applyGen2Status(st *gen2Status) {
	if s := st.Sys; s != nil {
		d.Uptime = s.Uptime
		d.FWStable, d.FWBeta = "", ""
		if u := s.AvailableUpdates.Stable; u != nil {
			d.FWStable = u.Version
		}
		if u := s.AvailableUpdates.Beta; u != nil {
			d.FWBeta = u.Version
		}
	}
	if w := st.Wifi; w != nil {
		if w.SSID != nil {
			d.SSID = *w.SSID
		}
		d.RSSI = w.RSSI
	}
	if st.Cloud != nil {
		c := st.Cloud.Connected
		d.Cloud = &c
	}
	if st.DevPower != nil && st.DevPower.Battery.Percent != nil {
		d.Battery = st.DevPower.Battery.Percent
		d.Sleepy = true
	}
}

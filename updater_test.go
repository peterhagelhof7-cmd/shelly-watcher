package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeUpdatable simuliert ein Shelly, das nach dem Update-Befehl kurz
// darauf mit neuer Version antwortet.
type fakeUpdatable struct {
	mu        sync.Mutex
	gen       int
	ver, next string
	calls     int
	broken    bool // Update wird angenommen, aber nie installiert
	srv       *httptest.Server
}

func (f *fakeUpdatable) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newFakeUpdatable(t *testing.T, gen int, ver, next string) *fakeUpdatable {
	f := &fakeUpdatable{gen: gen, ver: ver, next: next}
	mux := http.NewServeMux()
	stable := func() string { // Aufrufer hält f.mu
		if f.ver == f.next {
			return ""
		}
		return f.next
	}
	mux.HandleFunc("/shelly", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.gen == 1 {
			fmt.Fprintf(w, `{"type":"SHSW-1","mac":"E8DB84000001","auth":false,"fw":"20230913-112003/v%s-gcb84623"}`, f.ver)
		} else {
			fmt.Fprintf(w, `{"id":"shellyplus1-a8032a000002","mac":"A8032A000002","model":"SNSW-001X16EU","gen":2,"fw_id":"x/%s-g1","ver":"%s","app":"Plus1","auth_en":false}`, f.ver, f.ver)
		}
	})
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"device":{"hostname":"shelly1-000001"}}`)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		s := stable()
		fmt.Fprintf(w, `{"update":{"has_update":%v,"new_version":"20240101-000000/v%s-gabc","old_version":"x/v%s-g1"},"uptime":5}`, s != "", s, f.ver)
	})
	mux.HandleFunc("/rpc/Shelly.GetStatus", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if s := stable(); s != "" {
			fmt.Fprintf(w, `{"sys":{"uptime":5,"available_updates":{"stable":{"version":"%s"}}}}`, s)
		} else {
			fmt.Fprint(w, `{"sys":{"uptime":5,"available_updates":{}}}`)
		}
	})
	install := func(w http.ResponseWriter, body string) {
		f.mu.Lock()
		f.calls++
		broken := f.broken
		f.mu.Unlock()
		fmt.Fprint(w, body)
		if !broken {
			go func() {
				time.Sleep(30 * time.Millisecond)
				f.mu.Lock()
				f.ver = f.next
				f.mu.Unlock()
			}()
		}
	}
	mux.HandleFunc("/ota", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("update") != "true" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		install(w, `{"status":"updating","has_update":true}`)
	})
	mux.HandleFunc("/rpc/Shelly.Update", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("stage") != `"stable"` {
			http.Error(w, `{"code":-103,"message":"stage"}`, http.StatusInternalServerError)
			return
		}
		install(w, `null`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func testUpdater(rt *Runtime) (*Updater, *Store, *Prober) {
	st := newStore(rt)
	pr := newProber(rt, st)
	u := newUpdater(rt, st, pr)
	u.pollEvery, u.giveUpAfter = 10*time.Millisecond, 2*time.Second
	return u, st, pr
}

func waitUpdate(t *testing.T, st *Store, mac string, manual bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := st.get(mac); got.LastUpdate != nil && got.LastUpdate.State == "ok" && got.LastUpdate.Manual == manual {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := st.get(mac)
	t.Fatalf("Update nicht abgeschlossen: %+v", got.LastUpdate)
}

func TestInWindow(t *testing.T) {
	for _, c := range []struct {
		h, from, to int
		want        bool
	}{
		{3, 3, 5, true}, {4, 3, 5, true}, {5, 3, 5, false}, {2, 3, 5, false},
		{23, 22, 4, true}, {1, 22, 4, true}, {4, 22, 4, false}, {12, 22, 4, false},
		{12, 0, 0, true},
	} {
		if got := inWindow(c.h, c.from, c.to); got != c.want {
			t.Errorf("inWindow(%d, %d, %d) = %v", c.h, c.from, c.to, got)
		}
	}
}

func TestUpdateGen1AndGen2(t *testing.T) {
	for _, gen := range []int{1, 2} {
		f := newFakeUpdatable(t, gen, "1.4.4", "1.5.0")
		u, st, pr := testUpdater(testConfig(""))
		d, err := pr.probe(context.Background(), host(f.srv))
		if err != nil || d.FWStable != "1.5.0" {
			t.Fatalf("Gen%d Erstabfrage: %+v %v", gen, d, err)
		}
		st.apply(d, "scan")
		cand, ok := u.nextCandidate()
		if !ok {
			t.Fatalf("Gen%d sollte Kandidat sein", gen)
		}
		if err := u.update(context.Background(), cand, false); err != nil {
			t.Fatalf("Gen%d Update: %v", gen, err)
		}
		got, _ := st.get(d.MAC)
		if got.FWVersion != "1.5.0" || got.LastUpdate == nil || got.LastUpdate.State != "ok" ||
			got.LastUpdate.From != "1.4.4" || got.LastUpdate.To != "1.5.0" || f.callCount() != 1 {
			t.Fatalf("Gen%d nach Update: fw=%s last=%+v calls=%d", gen, got.FWVersion, got.LastUpdate, f.callCount())
		}
		if _, ok := u.nextCandidate(); ok {
			t.Fatalf("Gen%d: aktuelles Gerät darf kein Kandidat mehr sein", gen)
		}
	}
}

func TestUpdateFailsAndBacksOff(t *testing.T) {
	f := newFakeUpdatable(t, 2, "1.4.4", "1.5.0")
	f.broken = true
	u, st, pr := testUpdater(testConfig(""))
	u.giveUpAfter = 100 * time.Millisecond
	d, _ := pr.probe(context.Background(), host(f.srv))
	st.apply(d, "scan")
	cand, _ := u.nextCandidate()
	if err := u.update(context.Background(), cand, false); err == nil {
		t.Fatal("Update hätte fehlschlagen müssen")
	}
	got, _ := st.get(d.MAC)
	if got.LastUpdate == nil || got.LastUpdate.State != "failed" || !strings.Contains(got.LastUpdate.Detail, "Internet") {
		t.Fatalf("Fehlschlag nicht vermerkt: %+v", got.LastUpdate)
	}
	if _, ok := u.nextCandidate(); ok {
		t.Fatal("nach Fehlschlag 24 h Pause erwartet")
	}
	u.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if _, ok := u.nextCandidate(); !ok {
		t.Fatal("nach 24 h sollte es erneut versucht werden")
	}
}

func TestUpdateEligibility(t *testing.T) {
	u, _, _ := testUpdater(testConfig(""))
	base := Device{MAC: "X", IP: "1.2.3.4", Status: "online", FWVersion: "1.4.4", FWStable: "1.5.0", AuthStatus: "none"}
	if !u.eligible(&base) {
		t.Fatal("Basisfall sollte geeignet sein")
	}
	for name, mod := range map[string]func(*Device){
		"Ausnahme":       func(d *Device) { d.AutoUpdateOff = true },
		"schläft":        func(d *Device) { d.Sleepy = true },
		"offline":        func(d *Device) { d.Status = "offline" },
		"kein Update":    func(d *Device) { d.FWStable = "" },
		"Beta":           func(d *Device) { d.FWStable = "1.5.0-beta1" },
		"nicht neuer":    func(d *Device) { d.FWStable = "1.4.4" },
		"Passwort fehlt": func(d *Device) { d.AuthStatus = "missing" },
	} {
		d := base
		mod(&d)
		if u.eligible(&d) {
			t.Errorf("%s: darf nicht automatisch aktualisiert werden", name)
		}
	}
}

// Die Schleife aktualisiert nur, wenn aktiviert und im Zeitfenster.
func TestUpdaterRunRespectsSettingsAndWindow(t *testing.T) {
	f := newFakeUpdatable(t, 2, "1.4.4", "1.5.0")
	rt := testConfig("")
	u, st, pr := testUpdater(rt)
	d, _ := pr.probe(context.Background(), host(f.srv))
	st.apply(d, "scan")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hour sync.Mutex
	h := 12
	u.now = func() time.Time {
		hour.Lock()
		defer hour.Unlock()
		return time.Date(2026, 10, 11, h, 0, 0, 0, time.Local)
	}
	go u.run(ctx)
	kick := func() { u.trigger <- struct{}{}; time.Sleep(150 * time.Millisecond) }

	kick() // Auto-Update aus
	if f.callCount() != 0 {
		t.Fatal("Auto-Update ist aus, trotzdem aktualisiert")
	}
	if err := rt.set(Overrides{AutoUpdate: ptr(true), AutoUpdateFrom: ptr(3), AutoUpdateTo: ptr(5)}, false); err != nil {
		t.Fatal(err)
	}
	kick() // an, aber 12 Uhr liegt außerhalb 3-5
	if f.callCount() != 0 {
		t.Fatal("außerhalb des Zeitfensters aktualisiert")
	}
	hour.Lock()
	h = 4
	hour.Unlock()
	u.trigger <- struct{}{}
	waitUpdate(t, st, d.MAC, false)
}

func TestUpdateAPI(t *testing.T) {
	f := newFakeUpdatable(t, 2, "1.4.4", "1.5.0")
	rt := testConfig("")
	u, st, pr := testUpdater(rt)
	d, _ := pr.probe(context.Background(), host(f.srv))
	st.apply(d, "scan")
	st.apply(&Device{MAC: "BBBBBBBBBBBB", IP: "10.9.9.9", FWVersion: "1.5.0"}, "scan")
	srv := httptest.NewServer((&Web{cfg: rt, st: st, pr: pr, sc: newScanner(rt, pr), up: u}).handler())
	defer srv.Close()

	post := func(mac string) int {
		r, err := http.Post(srv.URL+"/api/devices/"+mac+"/update", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if c := post("BBBBBBBBBBBB"); c != http.StatusConflict {
		t.Fatalf("ohne verfügbares Update: %d", c)
	}
	// Ausnahme setzen: manuelles Update bleibt trotzdem möglich
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/devices/"+d.MAC+"/autoupdate", strings.NewReader(`{"enabled":false}`))
	r, err := http.DefaultClient.Do(req)
	if err != nil || r.StatusCode != http.StatusNoContent {
		t.Fatalf("Ausnahme setzen: %v %v", r, err)
	}
	if got, _ := st.get(d.MAC); !got.AutoUpdateOff {
		t.Fatal("Ausnahme nicht gespeichert")
	}
	if _, ok := u.nextCandidate(); ok {
		t.Fatal("Gerät mit Ausnahme darf nicht automatisch aktualisiert werden")
	}
	if c := post(d.MAC); c != http.StatusAccepted {
		t.Fatalf("manuelles Update: %d", c)
	}
	waitUpdate(t, st, d.MAC, true)
}

func ptr[T any](v T) *T { return &v }

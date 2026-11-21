package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeNamed simuliert ein Shelly, dessen Name sich setzen lässt.
type fakeNamed struct {
	mu   sync.Mutex
	gen  int
	mac  string
	name string
	srv  *httptest.Server
}

func newFakeNamed(t *testing.T, gen int) *fakeNamed {
	f := &fakeNamed{gen: gen, mac: "E8DB84000001", name: "Alt"}
	if gen >= 2 {
		f.mac = "A8032A000002"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/shelly", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.gen == 1 {
			fmt.Fprintf(w, `{"type":"SHSW-1","mac":"%s","auth":false,"fw":"20230913-112003/v1.14.0-gcb84623"}`, f.mac)
		} else {
			n, _ := json.Marshal(f.name)
			fmt.Fprintf(w, `{"id":"shellyplus1-a8032a000002","mac":"%s","model":"SNSW-001X16EU","gen":2,"fw_id":"x/1.4.4-g1","ver":"1.4.4","app":"Plus1","name":%s,"auth_en":false}`, f.mac, n)
		}
	})
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Query().Has("name") {
			f.name = r.URL.Query().Get("name")
		}
		n, _ := json.Marshal(f.name)
		fmt.Fprintf(w, `{"name":%s,"device":{"hostname":"shelly1-000001"}}`, n)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"uptime":5}`) })
	mux.HandleFunc("/rpc/Shelly.GetStatus", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"sys":{"uptime":5}}`) })
	mux.HandleFunc("/rpc/Sys.SetConfig", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Device struct {
				Name *string `json:"name"`
			} `json:"device"`
		}
		if json.Unmarshal([]byte(r.URL.Query().Get("config")), &req) != nil {
			http.Error(w, `{"code":-103}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.name = ""
		if req.Device.Name != nil {
			f.name = *req.Device.Name
		}
		f.mu.Unlock()
		fmt.Fprint(w, `{"restart_required":false}`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNamed) getName() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.name
}

func TestRenameAPI(t *testing.T) {
	for _, gen := range []int{1, 2} {
		t.Run(fmt.Sprintf("Gen%d", gen), func(t *testing.T) {
			f := newFakeNamed(t, gen)
			rt := testConfig("")
			_, st, pr := testUpdater(rt)
			d, err := pr.probe(context.Background(), host(f.srv))
			if err != nil {
				t.Fatal(err)
			}
			st.apply(d, "scan")
			if got, _ := st.get(d.MAC); got.Name != "Alt" || got.Status != "online" {
				t.Fatalf("Ausgangslage: %+v", got)
			}
			srv := httptest.NewServer((&Web{cfg: rt, st: st, pr: pr, sc: newScanner(rt, pr)}).handler())
			defer srv.Close()

			put := func(mac, body string) int {
				req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/devices/"+mac+"/name", strings.NewReader(body))
				r, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				r.Body.Close()
				return r.StatusCode
			}
			if c := put(d.MAC, `{"name":"  Küche & Flur \"links\"\n "}`); c != http.StatusNoContent {
				t.Fatalf("Umbenennen: %d", c)
			}
			want := `Küche & Flur "links"`
			if n := f.getName(); n != want {
				t.Fatalf("Gerät hat %q statt %q", n, want)
			}
			if got, _ := st.get(d.MAC); got.Name != want {
				t.Fatalf("Store hat %q", got.Name)
			}
			// leerer Name löscht
			if c := put(d.MAC, `{"name":""}`); c != http.StatusNoContent || f.getName() != "" {
				t.Fatalf("Löschen: %d, Gerät %q", c, f.getName())
			}
			if got, _ := st.get(d.MAC); got.Name != "" {
				t.Fatalf("Store nach Löschen: %q", got.Name)
			}
			if c := put(d.MAC, `{"name":"`+strings.Repeat("x", 65)+`"}`); c != http.StatusBadRequest {
				t.Fatalf("zu lang: %d", c)
			}
			if c := put("FFFFFFFFFFFF", `{"name":"x"}`); c != http.StatusNotFound {
				t.Fatalf("unbekannt: %d", c)
			}
			// anderes Gerät unter der IP: nichts schreiben
			f.mu.Lock()
			f.mac = "112233445566"
			f.mu.Unlock()
			if c := put(d.MAC, `{"name":"Falsch"}`); c != http.StatusBadGateway || f.getName() == "Falsch" {
				t.Fatalf("anderes Gerät: %d, Name %q", c, f.getName())
			}
		})
	}
}

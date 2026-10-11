package main

import (
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

// Outbound WebSocket: Gen2+-Geräte können sich selbst mit einem Server
// verbinden (Einstellungen -> Outbound WebSocket -> ws://<NAS>:8080/ws).
// Batteriegeräte wie Plus H&T, H&T Gen3, Plus Smoke oder Flood Gen4 tun das
// bei jedem Aufwachen - der einzige zuverlässige Weg, sie zu erfassen.
// Über die Verbindung fragen wir per JSON-RPC GetDeviceInfo und GetStatus ab.

type rpcFrame struct {
	ID     int             `json:"id"`
	Src    string          `json:"src"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

const (
	rpcInfo   = 1
	rpcStatus = 2
)

func (w *Web) wsServer() websocket.Server {
	return websocket.Server{
		// Shellys senden keinen Origin-Header; die Standardprüfung würde sie abweisen.
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler:   w.handleWS,
	}
}

func (w *Web) handleWS(conn *websocket.Conn) {
	defer conn.Close()
	ip := ""
	if ap, err := netip.ParseAddrPort(conn.Request().RemoteAddr); err == nil {
		ip = ap.Addr().Unmap().String()
	}
	d := &Device{IP: ip}
	var auth map[string]any
	// Jede Auth-Runde bekommt eigene Request-IDs (round*10 + rpcInfo/rpcStatus),
	// damit ein verspätetes 401 auf eine Anfrage ohne Auth nicht als
	// "Passwort falsch" gewertet wird.
	round := 0

	send := func(id int, method string) {
		req := map[string]any{"jsonrpc": "2.0", "id": id, "src": "shelly-watcher", "method": method}
		if auth != nil {
			req["auth"] = auth
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := websocket.JSON.Send(conn, req); err != nil {
			debugf("ws %s: %v", ip, err)
		}
	}
	sendAll := func() {
		send(round*10+rpcInfo, "Shelly.GetDeviceInfo")
		send(round*10+rpcStatus, "Shelly.GetStatus")
	}
	sendAll()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Minute))
		var raw []byte
		if err := websocket.Message.Receive(conn, &raw); err != nil {
			return
		}
		if len(raw) > maxBodyBytes {
			continue
		}
		var f rpcFrame
		if json.Unmarshal(raw, &f) != nil {
			continue
		}
		switch {
		case f.Error != nil && f.Error.Code == 401:
			if f.ID/10 < round {
				continue // Antwort auf eine ältere Runde
			}
			if w.cfg.ShellyPassword == "" || round > 0 {
				d.AuthEnable, d.AuthStatus = true, "missing"
				if round > 0 {
					d.AuthStatus = "failed"
				}
				if d.MAC == "" {
					d.ID, d.MAC = f.Src, macFromID(f.Src)
				}
				if d.MAC != "" {
					w.st.apply(d, "ws")
				}
				continue
			}
			var ch struct {
				Realm string `json:"realm"`
				Nonce int64  `json:"nonce"`
			}
			if json.Unmarshal([]byte(f.Error.Message), &ch) == nil && ch.Nonce != 0 {
				round++
				auth = rpcAuth("admin", w.cfg.ShellyPassword, ch.Realm, ch.Nonce, rand.Int64N(1<<31))
				sendAll()
			}
		case f.ID%10 == rpcInfo && f.Result != nil:
			var si shellyInfo
			if json.Unmarshal(f.Result, &si) == nil && si.MAC != "" {
				d.applyGen2Info(&si)
				if d.AuthStatus == "" {
					d.AuthStatus = authOK(si.AuthEn)
				}
				w.st.apply(d, "ws")
			}
		case f.ID%10 == rpcStatus && f.Result != nil:
			d.applyGen2Raw(f.Result)
			if d.MAC != "" {
				w.st.apply(d, "ws")
			}
		case f.Method == "NotifyFullStatus" || f.Method == "NotifyStatus":
			// Lebenszeichen; bei FullStatus auch die Werte übernehmen.
			if f.Method == "NotifyFullStatus" && len(f.Params) > 0 {
				// Status steht direkt in params; manche Firmware legt ihn unter params.status ab
				raw := f.Params
				var p struct {
					Status json.RawMessage `json:"status"`
				}
				if json.Unmarshal(f.Params, &p) == nil && len(p.Status) > 0 {
					raw = p.Status
				}
				d.applyGen2Raw(raw)
			}
			if d.MAC != "" {
				w.st.apply(d, "ws")
			}
		}
	}
}

// macFromID: "shellyplusht-08b61fcd1234" -> "08B61FCD1234".
func macFromID(id string) string {
	i := strings.LastIndexByte(id, '-')
	if i < 0 || len(id)-i-1 != 12 {
		return ""
	}
	if _, err := hex.DecodeString(id[i+1:]); err != nil {
		return ""
	}
	return strings.ToUpper(id[i+1:])
}

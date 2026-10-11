package main

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
)

// CoIoT (CoAP) ist das Gen1-Statusprotokoll: Gen1-Geräte senden ihren Status
// per Multicast an 224.0.1.187:5683. Batteriegeräte (H&T, Door/Window, Flood
// ...) sind nur kurz nach dem Aufwachen erreichbar - genau dann senden sie
// CoIoT. Wir fragen sie sofort ab und merken sie uns notfalls nur aus dem
// CoIoT-Paket (Option 3332 enthält Typ und MAC).

var coiotGroup = net.IPv4(224, 0, 1, 187)

const coiotOptGlobalDevID = 3332

func runCoIoT(ctx context.Context, cfg *Config, pr *Prober, st *Store) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 5683})
	if err != nil {
		log.Printf("CoIoT deaktiviert, Port 5683/udp nicht verfügbar: %v", err)
		return
	}
	go func() { <-ctx.Done(); conn.Close() }()

	pc := ipv4.NewPacketConn(conn)
	joined := 0
	seen := map[int]bool{}
	for _, li := range lanInterfaces(cfg) {
		if li.ifi.Flags&net.FlagMulticast == 0 || seen[li.ifi.Index] {
			continue
		}
		seen[li.ifi.Index] = true
		ifi := li.ifi
		if err := pc.JoinGroup(&ifi, &net.UDPAddr{IP: coiotGroup}); err != nil {
			debugf("CoIoT %s: %v", ifi.Name, err)
			continue
		}
		joined++
	}
	if joined == 0 {
		if err := pc.JoinGroup(nil, &net.UDPAddr{IP: coiotGroup}); err != nil {
			log.Printf("CoIoT: Multicast-Beitritt fehlgeschlagen (nur Unicast-CoIoT möglich): %v", err)
		}
	}
	log.Printf("CoIoT: lausche auf 5683/udp (%d Schnittstellen)", joined)

	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("CoIoT: %v", err)
			time.Sleep(time.Second)
			continue
		}
		typ, mac, ok := parseCoIoT(buf[:n])
		if !ok {
			continue
		}
		ip := from.Addr().Unmap().String()
		// Hinweis speichern (falls das Gerät gleich wieder einschläft) ...
		st.hint(&Device{MAC: mac, IP: ip, Gen: 1, Model: typ}, "coiot")
		// ... und sofort vollständig abfragen, solange es wach ist.
		pr.enqueue(ip, "coiot", false)
	}
}

// parseCoIoT liest Typ und MAC aus Option 3332 ("SHHT-1#AABBCCDDEEFF#2").
func parseCoIoT(b []byte) (typ, mac string, ok bool) {
	if len(b) < 4 || b[0]>>6 != 1 { // CoAP-Version 1
		return "", "", false
	}
	tkl := int(b[0] & 0x0f)
	i := 4 + tkl
	opt := 0
	for i < len(b) && b[i] != 0xff {
		delta, length := int(b[i]>>4), int(b[i]&0x0f)
		i++
		var okd, okl bool
		if delta, i, okd = coapExt(b, i, delta); !okd {
			return "", "", false
		}
		if length, i, okl = coapExt(b, i, length); !okl {
			return "", "", false
		}
		opt += delta
		if i+length > len(b) {
			return "", "", false
		}
		if opt == coiotOptGlobalDevID {
			parts := strings.Split(string(b[i:i+length]), "#")
			if len(parts) >= 2 && strings.HasPrefix(parts[0], "SH") && len(parts[1]) >= 6 {
				return parts[0], normMAC(parts[1]), true
			}
			return "", "", false
		}
		i += length
	}
	return "", "", false
}

// coapExt dekodiert die erweiterten Delta-/Längenfelder (13 und 14).
func coapExt(b []byte, i, v int) (int, int, bool) {
	switch v {
	case 13:
		if i >= len(b) {
			return 0, i, false
		}
		return int(b[i]) + 13, i + 1, true
	case 14:
		if i+1 >= len(b) {
			return 0, i, false
		}
		return int(b[i])<<8 | int(b[i+1]) + 269, i + 2, true
	case 15:
		return 0, i, false
	}
	return v, i, true
}

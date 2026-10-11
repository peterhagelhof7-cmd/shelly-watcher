package main

import (
	"context"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// mDNS-Suche nach _shelly._tcp (Gen2+) und _http._tcp (Gen1 meldet sich als
// shellyXXX-<mac>). Wir senden von einem zufälligen Port ("legacy unicast",
// RFC 6762 6.7): die Geräte antworten direkt an diesen Port. So brauchen wir
// Port 5353 nicht, den auf der Synology bereits avahi belegt.

var mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

var mdnsServices = []string{"_shelly._tcp.local.", "_http._tcp.local."}

func runMDNS(ctx context.Context, cfg *Config, pr *Prober) {
	t := time.NewTicker(cfg.MDNSInterval)
	defer t.Stop()
	for {
		if err := mdnsQuery(ctx, cfg, pr); err != nil {
			log.Printf("mDNS: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func buildMDNSQuery() ([]byte, error) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 128), dnsmessage.Header{})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, s := range mdnsServices {
		if err := b.Question(dnsmessage.Question{
			Name:  dnsmessage.MustNewName(s),
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func mdnsQuery(ctx context.Context, cfg *Config, pr *Prober) error {
	query, err := buildMDNSQuery()
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return err
	}
	defer conn.Close()
	pc := ipv4.NewPacketConn(conn)
	_ = pc.SetMulticastTTL(255)

	sent := 0
	seen := map[int]bool{}
	for _, li := range lanInterfaces(cfg) {
		if li.ifi.Flags&net.FlagMulticast == 0 || seen[li.ifi.Index] {
			continue
		}
		seen[li.ifi.Index] = true
		ifi := li.ifi
		if err := pc.SetMulticastInterface(&ifi); err != nil {
			debugf("mDNS %s: %v", ifi.Name, err)
			continue
		}
		if _, err := conn.WriteTo(query, mdnsGroup); err != nil {
			debugf("mDNS %s: %v", ifi.Name, err)
			continue
		}
		sent++
	}
	if sent == 0 {
		// Fallback: Standardroute (z.B. wenn alle Interfaces gefiltert wurden)
		if _, err := conn.WriteTo(query, mdnsGroup); err != nil {
			return err
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 9000)
	found := 0
	for ctx.Err() == nil {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		for _, ip := range parseMDNSResponse(buf[:n], from.Addr().Unmap()) {
			found++
			pr.enqueue(ip.String(), "mdns", false)
		}
	}
	debugf("mDNS: %d Shelly-Antworten", found)
	return nil
}

// parseMDNSResponse gibt die IPs zurück, die zu einem Shelly gehören. Das
// ist die Absender-IP, wenn irgendein Name in der Antwort "shelly" enthält
// (bzw. die Antwort zu _shelly._tcp gehört), plus passende A-Records.
func parseMDNSResponse(msg []byte, from netip.Addr) []netip.Addr {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response {
		return nil
	}
	_ = p.SkipAllQuestions()
	isShelly := false
	var addrs []netip.Addr
	check := func(rr dnsmessage.Resource) {
		name := strings.ToLower(rr.Header.Name.String())
		if strings.Contains(name, "shelly") {
			isShelly = true
		}
		switch b := rr.Body.(type) {
		case *dnsmessage.PTRResource:
			if strings.Contains(strings.ToLower(b.PTR.String()), "shelly") {
				isShelly = true
			}
		case *dnsmessage.SRVResource:
			if strings.Contains(strings.ToLower(b.Target.String()), "shelly") {
				isShelly = true
			}
		case *dnsmessage.AResource:
			if strings.Contains(name, "shelly") {
				addrs = append(addrs, netip.AddrFrom4(b.A))
			}
		}
	}
	for _, section := range []func() ([]dnsmessage.Resource, error){p.AllAnswers, p.AllAuthorities, p.AllAdditionals} {
		rrs, err := section()
		if err != nil {
			break
		}
		for _, rr := range rrs {
			check(rr)
		}
	}
	if !isShelly {
		return nil
	}
	if len(addrs) == 0 && from.Is4() {
		addrs = append(addrs, from)
	}
	return addrs
}

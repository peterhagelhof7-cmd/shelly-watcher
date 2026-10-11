package main

import (
	"context"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type lanIface struct {
	ifi    net.Interface
	addr   netip.Addr
	prefix netip.Prefix
}

// lanInterfaces liefert alle aktiven IPv4-Schnittstellen außer Loopback und
// virtuellen Docker-/VM-/VPN-Brücken (SKIP_IFACES).
func lanInterfaces(cfg *Config) []lanIface {
	ifs, err := net.Interfaces()
	if err != nil {
		log.Printf("Netzwerkschnittstellen nicht lesbar: %v", err)
		return nil
	}
	var out []lanIface
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || skipIface(cfg, ifi.Name) {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() || ip.IsLinkLocalUnicast() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			out = append(out, lanIface{ifi: ifi, addr: ip, prefix: netip.PrefixFrom(ip, ones).Masked()})
		}
	}
	return out
}

func skipIface(cfg *Config, name string) bool {
	for _, p := range cfg.SkipIfaces {
		if p = strings.TrimSpace(p); p != "" && strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Scanner prüft periodisch alle Adressen der LAN-Netze auf offenen Port 80
// und lässt offene Adressen vom Prober untersuchen.
type Scanner struct {
	cfg      *Config
	pr       *Prober
	running  atomic.Bool
	mu       sync.Mutex
	lastScan time.Time
	lastNets []string
	trigger  chan struct{}
}

func newScanner(cfg *Config, pr *Prober) *Scanner {
	return &Scanner{cfg: cfg, pr: pr, trigger: make(chan struct{}, 1)}
}

func (s *Scanner) run(ctx context.Context) {
	t := time.NewTicker(s.cfg.ScanInterval)
	defer t.Stop()
	for {
		s.scan(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.trigger:
		}
	}
}

// requestScan stößt einen Scan an; false, wenn bereits einer läuft.
func (s *Scanner) requestScan() bool {
	if s.running.Load() {
		return false
	}
	select {
	case s.trigger <- struct{}{}:
	default:
	}
	return true
}

func (s *Scanner) targets() []netip.Prefix {
	if len(s.cfg.ScanCIDRs) > 0 {
		return s.cfg.ScanCIDRs
	}
	var nets []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, li := range lanInterfaces(s.cfg) {
		p := li.prefix
		if p.Bits() < 22 {
			// Großes Netz: automatisch nur das eigene /24 scannen.
			log.Printf("%s: Netz %s ist groß, scanne automatisch nur %s (für mehr SCAN_CIDRS setzen)",
				li.ifi.Name, p, netip.PrefixFrom(li.addr, 24).Masked())
			p = netip.PrefixFrom(li.addr, 24).Masked()
		}
		if !seen[p] {
			seen[p] = true
			nets = append(nets, p)
		}
	}
	return nets
}

func (s *Scanner) scan(ctx context.Context) {
	if !s.running.CompareAndSwap(false, true) {
		return
	}
	defer s.running.Store(false)

	nets := s.targets()
	if len(nets) == 0 {
		log.Printf("Scan: keine Netze gefunden - im Bridge-Modus SCAN_CIDRS setzen oder network_mode: host verwenden")
		return
	}
	start := time.Now()
	names := make([]string, len(nets))
	for i, n := range nets {
		names[i] = n.String()
	}
	debugf("Scan startet: %s", strings.Join(names, ", "))

	sem := make(chan struct{}, s.cfg.ScanConcurrency)
	var wg sync.WaitGroup
	var hits atomic.Int32
	d := net.Dialer{Timeout: 700 * time.Millisecond}
	for _, n := range nets {
		for ip := range hosts(n) {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(ip string) {
				defer func() { <-sem; wg.Done() }()
				c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip, "80"))
				if err != nil {
					return
				}
				c.Close()
				hits.Add(1)
				s.pr.submit(ctx, ip, "scan")
			}(ip.String())
		}
	}
	wg.Wait()
	s.mu.Lock()
	s.lastScan, s.lastNets = time.Now(), names
	s.mu.Unlock()
	log.Printf("Scan %s fertig in %s, %d Hosts mit Port 80", strings.Join(names, ", "),
		time.Since(start).Round(time.Second), hits.Load())
}

// hosts liefert alle Hostadressen eines Netzes (ohne Netz- und Broadcastadresse).
func hosts(p netip.Prefix) func(func(netip.Addr) bool) {
	return func(yield func(netip.Addr) bool) {
		p = p.Masked()
		a := p.Addr()
		if p.Bits() >= 31 {
			for ; p.Contains(a); a = a.Next() {
				if !yield(a) {
					return
				}
			}
			return
		}
		for a = a.Next(); p.Contains(a.Next()); a = a.Next() {
			if !yield(a) {
				return
			}
		}
	}
}

func (s *Scanner) info() (time.Time, []string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastScan, s.lastNets, s.running.Load()
}

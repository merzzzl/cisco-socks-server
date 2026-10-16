package service

import (
	"maps"
	"sync"
	"time"
)

// discoveredClientTTL is how long a discovered client stays pinned after it
// was last seen on Accept (live connections keep it regardless).
const discoveredClientTTL = 30 * time.Minute

type clientEntry struct {
	lastSeen time.Time
	mac      string // empty until learned from ARP
	static   bool   // from lan_clients: never expires
}

// clientRegistry is the set of LAN clients the pinner keeps reachable:
// static ones from lan_clients plus ones discovered on Accept. Keyed by IP.
type clientRegistry struct {
	clients map[string]*clientEntry
	mu      sync.Mutex
}

func newClientRegistry(static []LANClient) *clientRegistry {
	r := &clientRegistry{clients: make(map[string]*clientEntry, len(static))}

	for _, lc := range static {
		r.clients[lc.IP] = &clientEntry{mac: lc.MAC, static: true}
	}

	return r
}

// seen records a client observed on Accept and reports whether it is new.
// An empty mac never overwrites a known one.
func (r *clientRegistry) seen(ip, mac string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.clients[ip]
	if !ok {
		e = &clientEntry{}
		r.clients[ip] = e
	}

	if mac != "" {
		e.mac = mac
	}

	e.lastSeen = now

	return !ok
}

func (r *clientRegistry) lookup(ip string) (mac string, lastSeen time.Time, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.clients[ip]
	if !ok {
		return "", time.Time{}, false
	}

	return e.mac, e.lastSeen, true
}

// setMAC adopts the MAC the kernel resolved for a known client.
func (r *clientRegistry) setMAC(ip, mac string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if e, ok := r.clients[ip]; ok {
		e.mac = mac
	}
}

// snapshot returns ip → mac for all clients; the map is a copy.
func (r *clientRegistry) snapshot() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make(map[string]string, len(r.clients))
	for ip, e := range r.clients {
		out[ip] = e.mac
	}

	return out
}

// expire drops discovered clients not seen for ttl, except IPs in live (they
// still have open connections, e.g. a long SSH session), and returns them.
func (r *clientRegistry) expire(now time.Time, ttl time.Duration, live map[string]bool) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var expired []string

	maps.DeleteFunc(r.clients, func(ip string, e *clientEntry) bool {
		if e.static || live[ip] || now.Sub(e.lastSeen) < ttl {
			return false
		}

		expired = append(expired, ip)

		return true
	})

	return expired
}

// resetNetwork forgets what belonged to the previous network: discovered
// clients are dropped and static ones lose their MAC, so a home-network MAC
// is never force-pinned onto whoever holds that IP in the new network. The
// static MAC is re-learned from ARP (route.PinAdopt).
func (r *clientRegistry) resetNetwork() {
	r.mu.Lock()
	defer r.mu.Unlock()

	maps.DeleteFunc(r.clients, func(_ string, e *clientEntry) bool {
		return !e.static
	})

	for _, e := range r.clients {
		e.mac = ""
	}
}

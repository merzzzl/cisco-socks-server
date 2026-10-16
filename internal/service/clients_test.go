package service

import (
	"maps"
	"slices"
	"testing"
	"time"
)

const (
	staticIP     = "192.168.0.42"
	staticMAC    = "72:ce:39:12:45:0f"
	discoveredIP = "192.168.0.214"
	learnedMAC   = "12:49:61:d3:72:48"
)

func TestClientRegistrySeen(t *testing.T) {
	t.Parallel()

	r := newClientRegistry(nil)
	t0 := time.Unix(1000, 0)

	if !r.seen(discoveredIP, learnedMAC, t0) {
		t.Error("first seen must report a new client")
	}

	if r.seen(discoveredIP, "", t0.Add(time.Minute)) {
		t.Error("second seen must not report a new client")
	}

	mac, last, ok := r.lookup(discoveredIP)
	if !ok || mac != learnedMAC || !last.Equal(t0.Add(time.Minute)) {
		t.Errorf("lookup = %q, %v, %v; want known MAC kept and lastSeen bumped", mac, last, ok)
	}

	r.seen(discoveredIP, staticMAC, t0)

	if mac, _, _ := r.lookup(discoveredIP); mac != staticMAC {
		t.Errorf("seen with a MAC must update it, got %q", mac)
	}
}

func TestClientRegistryExpire(t *testing.T) {
	t.Parallel()

	r := newClientRegistry([]LANClient{{IP: staticIP, MAC: staticMAC}})
	t0 := time.Unix(1000, 0)

	r.seen(discoveredIP, learnedMAC, t0)
	r.seen("192.168.0.7", "", t0)
	r.seen("192.168.0.8", "", t0.Add(20*time.Minute))

	now := t0.Add(discoveredClientTTL)
	got := r.expire(now, discoveredClientTTL, map[string]bool{"192.168.0.7": true})

	if !slices.Equal(got, []string{discoveredIP}) {
		t.Errorf("expire() = %v, want only the stale client without live conns", got)
	}

	want := map[string]string{staticIP: staticMAC, "192.168.0.7": "", "192.168.0.8": ""}
	if snap := r.snapshot(); !maps.Equal(snap, want) {
		t.Errorf("snapshot() = %v, want %v", snap, want)
	}
}

func TestClientRegistryResetNetwork(t *testing.T) {
	t.Parallel()

	r := newClientRegistry([]LANClient{{IP: staticIP, MAC: staticMAC}})
	r.seen(discoveredIP, learnedMAC, time.Unix(1000, 0))

	r.resetNetwork()

	want := map[string]string{staticIP: ""}
	if snap := r.snapshot(); !maps.Equal(snap, want) {
		t.Errorf("snapshot() = %v, want %v", snap, want)
	}

	r.setMAC(staticIP, learnedMAC)
	r.setMAC(discoveredIP, learnedMAC) // unknown IP: no-op

	want = map[string]string{staticIP: learnedMAC}
	if snap := r.snapshot(); !maps.Equal(snap, want) {
		t.Errorf("after setMAC snapshot() = %v, want %v", snap, want)
	}
}

func TestClientRegistrySnapshotIsCopy(t *testing.T) {
	t.Parallel()

	r := newClientRegistry([]LANClient{{IP: staticIP, MAC: staticMAC}})

	snap := r.snapshot()
	snap[staticIP] = "changed"

	if mac, _, _ := r.lookup(staticIP); mac != staticMAC {
		t.Errorf("mutating the snapshot changed the registry: %q", mac)
	}
}

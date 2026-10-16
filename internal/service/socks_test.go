package service

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// socksExchange serves one connection with server-side sv and writes req
// from the client side, returning the first n reply bytes.
func socksExchange(t *testing.T, s *Service, lan bool, req []byte, n int) []byte {
	t.Helper()

	client, server := net.Pipe()
	defer client.Close()

	go func() { _ = s.newSocksServer(lan).ServeConn(server) }()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := client.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}

	reply := make([]byte, n)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	return reply
}

func connectIPv4(ip net.IP, port int) []byte {
	return append([]byte{5, 1, 0, 1}, append(ip.To4(), byte(port>>8), byte(port))...)
}

func connectFQDN(name string, port int) []byte {
	req := append([]byte{5, 1, 0, 3, byte(len(name))}, name...)

	return append(req, byte(port>>8), byte(port))
}

func connected(s *Service, up bool) {
	s.setStatus(func(st *State) { st.CiscoConnected = up })
}

func TestSocksAuth(t *testing.T) {
	t.Parallel()

	s := New(Options{SocksUser: "proxy", SocksPassword: "secret"})

	// LAN without credentials: no acceptable method
	if got := socksExchange(t, s, true, []byte{5, 1, 0}, 2); !bytes.Equal(got, []byte{5, 0xff}) {
		t.Errorf("LAN no-auth greeting = %x, want 05ff", got)
	}

	// LAN with credentials
	creds := []byte{5, 1, 2, 1, 5}
	creds = append(creds, "proxy"...)
	creds = append(creds, 6)
	creds = append(creds, "secret"...)

	if got := socksExchange(t, s, true, creds, 4); !bytes.Equal(got, []byte{5, 2, 1, 0}) {
		t.Errorf("LAN user/pass = %x, want 0502 0100", got)
	}

	wrong := append([]byte{5, 1, 2, 1, 5}, "proxy"...)
	wrong = append(wrong, 5)
	wrong = append(wrong, "wrong"...)

	if got := socksExchange(t, s, true, wrong, 4); got[3] == 0 {
		t.Errorf("LAN wrong password = %x, want a failure status", got)
	}

	// loopback stays open
	if got := socksExchange(t, s, false, []byte{5, 1, 0}, 2); !bytes.Equal(got, []byte{5, 0}) {
		t.Errorf("loopback greeting = %x, want 0500", got)
	}
}

func TestVPNGate(t *testing.T) {
	t.Parallel()

	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}

			_ = c.Close()
		}
	}()

	addr, ok := target.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %v is not TCP", target.Addr())
	}

	greeting := []byte{5, 1, 0}

	s := New(Options{})

	// VPN down: IP destination gets network unreachable without a dial
	connected(s, false)

	got := socksExchange(t, s, false, append(greeting, connectIPv4(addr.IP, addr.Port)...), 4)
	if got[3] != 0x03 {
		t.Errorf("IP connect without VPN: reply %#x, want 0x03", got[3])
	}

	// VPN down: FQDN is not resolved, host unreachable
	got = socksExchange(t, s, false, append(greeting, connectFQDN("localhost", addr.Port)...), 4)
	if got[3] != 0x04 {
		t.Errorf("FQDN connect without VPN: reply %#x, want 0x04", got[3])
	}

	// VPN up: the request goes through
	connected(s, true)

	got = socksExchange(t, s, false, append(greeting, connectIPv4(addr.IP, addr.Port)...), 4)
	if got[3] != 0x00 {
		t.Errorf("connect with VPN: reply %#x, want success", got[3])
	}
}

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"

	yaml "gopkg.in/yaml.v3"

	"github.com/merzzzl/cisco-socks-server/internal/service"
)

type Config struct {
	CiscoUser     string              `yaml:"user"`
	CiscoPassword string              `yaml:"password"`
	CiscoProfile  string              `yaml:"profile"`
	SocksUser     string              `yaml:"socks_user"`
	SocksPassword string              `yaml:"socks_password"`
	DNSServers    []string            `yaml:"dns_servers"`
	LANClients    []service.LANClient `yaml:"lan_clients"`
	LANDiscovery  bool                `yaml:"lan_discovery"`
	noTUI         bool
	debug         bool
}

func loadConfig() (*Config, error) {
	var cfg Config

	flag.BoolVar(&cfg.noTUI, "no-tui", false, "disable TUI, use plain log output")
	flag.BoolVar(&cfg.debug, "debug", false, "enable debug logging")
	flag.Parse()

	name, ok := os.LookupEnv("SUDO_USER")
	if !ok || name == "" {
		return nil, fmt.Errorf("SUDO_USER is not set, run with sudo")
	}

	usr, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup user %q: %w", name, err)
	}

	data, err := os.ReadFile(filepath.Join(usr.HomeDir, ".cisco-socks5.yaml"))
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.CiscoUser == "" {
		return fmt.Errorf("config: user is required")
	}

	if c.CiscoPassword == "" {
		return fmt.Errorf("config: password is required")
	}

	if c.CiscoProfile == "" {
		return fmt.Errorf("config: profile is required")
	}

	if len(c.DNSServers) == 0 {
		return fmt.Errorf("config: dns_servers is required")
	}

	// plain IPs only: queries go to <ip>:53, and a hostname would have to be
	// resolved through this very DNS server
	for i, srv := range c.DNSServers {
		if net.ParseIP(srv) == nil {
			return fmt.Errorf("config: dns_servers[%d]: invalid IP address %q", i, srv)
		}
	}

	// fail fast on malformed lan_clients: at runtime a bad entry would only
	// surface as a debug-level "pin skipped" message every poll tick
	for i, lc := range c.LANClients {
		if ip := net.ParseIP(lc.IP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("config: lan_clients[%d]: invalid IPv4 address %q", i, lc.IP)
		}

		// optional: learned from ARP when empty
		if lc.MAC == "" {
			continue
		}

		if _, err := net.ParseMAC(lc.MAC); err != nil {
			return fmt.Errorf("config: lan_clients[%d]: invalid MAC %q: %w", i, lc.MAC, err)
		}
	}

	if (c.SocksUser == "") != (c.SocksPassword == "") {
		return fmt.Errorf("config: socks_user and socks_password must be set together")
	}

	return nil
}

func (c *Config) serviceOptions() service.Options {
	return service.Options{
		CiscoUser:     c.CiscoUser,
		CiscoPassword: c.CiscoPassword,
		CiscoProfile:  c.CiscoProfile,
		DNSServers:    c.DNSServers,
		LANClients:    c.LANClients,
		SocksUser:     c.SocksUser,
		SocksPassword: c.SocksPassword,
		LANDiscovery:  c.LANDiscovery,
	}
}

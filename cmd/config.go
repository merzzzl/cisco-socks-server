package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	yaml "gopkg.in/yaml.v3"
)

type Config struct {
	CiscoUser     string `yaml:"user"`
	CiscoPassword string `yaml:"password"`
	CiscoProfile  string `yaml:"profile"`
	noTUI bool
	debug bool
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

	return nil
}

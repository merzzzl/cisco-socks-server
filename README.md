# cisco-socks-server

SOCKS5 proxy through Cisco AnyConnect VPN.

## Install

Download binary from [Releases](https://github.com/merzzzl/cisco-socks-server/releases):

```bash
curl -L -o cisco-socks-server https://github.com/merzzzl/cisco-socks-server/releases/latest/download/cisco-socks-server-darwin-arm64
chmod +x cisco-socks-server
```

## Config

Create `~/.cisco-socks5.yaml`:

```yaml
user: your-vpn-username
password: your-vpn-password
profile: your-vpn-profile
```

## Run

```bash
sudo ./cisco-socks-server
```

Proxy will be available at `localhost:8080`.

### Flags

- `--no-tui` — disable TUI, plain log output
- `--debug` — enable debug logging

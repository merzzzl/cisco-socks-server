# cisco-socks-server

SOCKS5 proxy through Cisco AnyConnect VPN.

Fork of [merzzzl/cisco-socks-server](https://github.com/merzzzl/cisco-socks-server).

## Differences from the original

- **Reachable from LAN devices.** The SOCKS5 listener binds to `0.0.0.0:8080` and pins itself to the detected LAN interface via `IP_BOUND_IF`, so reply traffic egresses through the physical NIC even though Cisco hijacks `192.168.x.x` routes into the tunnel. Other devices on your network can use `<mac-lan-ip>:8080` as their proxy.
- **Built-in DNS server.** Listens on TCP `127.0.0.1:53` and forwards queries over UDP to the corporate DNS servers from the config (`dns_servers`) — for clients that can't resolve intranet names through SOCKS5 alone.
- **Packet filter disabled after connect.** Runs `pfctl -d` once the VPN is up, so LAN clients aren't blocked by the firewall rules Cisco installs.
- **Survives network changes.** The LAN interface and subnet are re-detected while running; switching Wi-Fi networks re-binds the LAN listener without a restart. LAN clients can be discovered automatically (with SOCKS auth), and a rotating private Wi-Fi MAC of a client is picked up from ARP instead of being overwritten.
- **No leaks while the VPN is down.** CONNECT requests are refused (`network unreachable`) and destination names are not resolved until the VPN is connected again.
- **Resilient supervisor.** The service never exits on VPN connect failures: it retries forever with exponential backoff (5s → 1min), waits instead of interfering while the Cisco agent is reconnecting on its own (network drop, laptop sleep), and verifies connect results via `vpn -s state` instead of parsing the unordered `-s connect` event stream (which reported false failures).
- **`dns_servers` is a required config key** (see below).

## Install

Build from source (Go 1.24+):

```bash
git clone https://github.com/tiptop32/cisco-socks-server.git
cd cisco-socks-server
make build
```

## Config

Create `~/.cisco-socks5.yaml`:

```yaml
user: your-vpn-username
password: your-vpn-password
profile: your-vpn-profile
dns_servers:
  - 10.0.0.1
  - 10.0.0.2
# optional: SOCKS5 username/password for LAN clients (loopback stays open);
# also enables automatic discovery of LAN clients
socks_user: proxy
socks_password: change-me
# optional: LAN hosts that must reach the proxy while the VPN is up;
# mac is optional and learned from ARP when omitted
lan_clients:
  - ip: 192.168.0.42
    mac: 72:ce:39:12:45:0f
# optional: discover LAN clients without socks_user (open proxy for
# everyone on the network)
# lan_discovery: true
```

`dns_servers` must be plain IP addresses. LAN clients are pinned to the LAN
interface (per-host route + static ARP), because Cisco routes the LAN subnet
into the tunnel and replies would otherwise never reach them.

Which LAN clients get pinned:

- with `socks_user`/`socks_password`, any client that connects from the LAN
  subnet is discovered automatically (and forgotten 30 minutes after its last
  connection); `lan_clients` is not needed;
- with `lan_discovery: true` the same happens without auth — anyone on the
  same network (café, hotel Wi-Fi) can then use the proxy into your VPN;
- otherwise only `lan_clients` are pinned, as before.

A `lan_clients` entry from one network is not pinned in another one: only
clients inside the current LAN subnet are.

### Using it with twarp

[twarp](https://github.com/tiptop32/twarp) routes gateway traffic through this
proxy (`gateway.socks: <mac-lan-ip>:8080`). With `socks_user` set here, store
the same credentials in twarp's `secrets.yaml` first (`twarp gateway auth`),
otherwise twarp gets an authentication failure.

## Run

```bash
sudo ./cisco-socks-server
```

Proxy will be available at `localhost:8080`. Requests are refused while the
VPN is not connected.

The SOCKS5 listener binds itself to the detected LAN interface
(`IP_BOUND_IF`), so reply traffic egresses via the physical NIC even though
Cisco hijacks the routing table for `192.168.x.x` into the VPN tunnel. This
keeps the proxy reachable from other devices on your local network
(e.g., `curl --socks5 <mac-lan-ip>:8080 ...`).

### Flags

- `--no-tui` — disable TUI, plain log output
- `--debug` — enable debug logging

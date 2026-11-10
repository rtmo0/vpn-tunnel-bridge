# Bridge

**Tunnel Bridge** — an open-source VPN client for macOS.

Bridge runs VPN backends as a privileged helper over plain `utun` interfaces,
so it needs no Network Extension entitlement and no Apple Developer account,
and it can run several tunnels side by side.

## Status

Early development. Working today:

- **AmneziaWG** with every parameter of protocol versions 1.0, 1.5 and 2.0
  (`Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4` incl. ranges, `I1`–`I5`,
  `HeaderProtectionKey`, `ContentPaddingAddition`, timing options, …)
- **WireGuard** (same backend, without obfuscation)
- Full-tunnel and split-tunnel routing, DNS, several tunnels at once
- Command-line client

Planned: menu bar app, OpenVPN, reconnect on network change, kill switch.

Unknown config keys are **rejected with a clear error**, never silently dropped.

## Requirements

- macOS 13 or later
- Xcode command-line tools (Swift 6)
- Go (to build `amneziawg-go`): `brew install go`

## Build and install

```bash
scripts/build.sh          # as your user: builds CLI, helper and amneziawg-go
sudo scripts/install.sh   # installs the launchd helper and /usr/local/bin/bridge
```

Uninstall: `sudo scripts/install.sh --uninstall`

## Usage

```bash
bridge check my-server.conf     # validate and show what will be applied
bridge import my-server.conf    # save to ~/Library/Application Support/Bridge/Tunnels
bridge up my-server             # connect
bridge status                   # handshake, traffic, interface
bridge down my-server           # disconnect (or: bridge down --all)
bridge list
```

Logs: `/var/log/bridge/helper.log` and `/var/log/bridge/<tunnel>.log`.

## How it works

```
bridge (CLI, your user) ──JSON over /var/run/bridge/helper.sock──▶ bridge-helper (root, launchd)
                                                                       │
                                     ┌─────────────────────────────────┼────────────────────────┐
                                     ▼                                 ▼                        ▼
                         amneziawg-go -f utun          route / ifconfig (addresses,   SystemConfiguration
                         configured over its UAPI      split default route, pinned    (DNS, as temporary
                         socket /var/run/amneziawg     route to the server)           keys of the helper)
```

- The helper talks to `amneziawg-go` directly over the UAPI socket, so every
  parameter in the config reaches the backend.
- A full tunnel uses `0.0.0.0/1` + `128.0.0.0/1` (and `::/1` + `8000::/1`), and
  the route to the VPN server is pinned to the current uplink first.
- DNS settings are published as temporary dynamic-store keys: if the helper dies,
  macOS removes them automatically.
- Routes and backend PIDs are recorded in `/var/run/bridge/state.json`; a
  restarted helper cleans up whatever a crashed one left behind.

## Security

- Only root and members of the `admin` group can talk to the helper (checked with `getpeereid`).
- The helper refuses to execute a backend that is not owned by root or is writable by others.
- `PreUp`/`PostUp`/`PreDown`/`PostDown` are ignored: Bridge never runs commands from config files.
- Private keys never appear in logs.

## Third-party components

- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) (MIT), built from source by `scripts/build-backend.sh`.

## License

MIT, see [LICENSE](LICENSE).

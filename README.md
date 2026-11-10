# Bridge

**Tunnel Bridge** — an open-source VPN client for macOS that lives in the menu bar.

Bridge runs VPN backends through a privileged helper over plain `utun` interfaces,
so it needs no Network Extension entitlement and no Apple Developer account,
and it can run several tunnels side by side.

## Protocols

| Protocol | Backend | Notes |
|---|---|---|
| **AmneziaWG** | [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) | every parameter of versions 1.0, 1.5 and 2.0: `Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4` (incl. ranges), `I1`–`I5`, `HeaderProtectionKey`, `ContentPaddingAddition`, timing options |
| **WireGuard** | amneziawg-go | wire-compatible when no obfuscation is set |
| **OpenVPN** | [OpenVPN 2.7](https://github.com/OpenVPN/openvpn) | username/password, certificates, encrypted keys, static challenge (OTP), pushed DNS |

Unknown WireGuard/AmneziaWG keys are **rejected with a clear error**, never silently dropped.

## Build

Requirements: macOS 14+, Xcode command-line tools, Homebrew.

```bash
brew install go openssl@3 lz4 lzo pkgconf
scripts/build-openvpn.sh   # once: builds OpenVPN with static OpenSSL (optional)
scripts/build.sh           # builds everything and assembles build/Bridge.app
open build/Bridge.app
```

On first launch click **Install Helper…** in the menu and enter your password.
The helper is a launchd daemon; tunnels keep running when the app is closed.

## Using the app

- **Import…** — pick `.conf` (WireGuard / AmneziaWG) or `.ovpn` files. Certificates
  and keys referenced by an `.ovpn` are embedded; `auth-user-pass` files go to the Keychain.
- Flip the switch to connect. OpenVPN asks for credentials when needed and can
  remember them in the Keychain.
- Right-click a tunnel to remove it, forget its password or show it in Finder.
- **Logs** opens `/var/log/bridge` (`helper.log` and one log per tunnel).

## Command line

The helper installation also puts `bridge` in `/usr/local/bin`:

```bash
bridge import my-server.conf
bridge up my-server
bridge status
bridge down my-server        # or: bridge down --all
bridge check file.ovpn       # validate without connecting
```

## How it works

```
Bridge.app / bridge CLI (your user)
        │  JSON over /var/run/bridge/helper.sock (admin users only)
        ▼
bridge-helper (root, launchd)
  ├─ amneziawg-go -f utun   configured over its UAPI socket; Bridge sets addresses,
  │                         split default route (0/1 + 128/1), pinned server route
  ├─ openvpn                driven via its management socket; configures utun and
  │                         routes itself, Bridge answers password prompts
  └─ DNS                    System Configuration dynamic store, temporary keys
```

- DNS settings are temporary dynamic-store keys of the helper: if it dies, macOS
  removes them automatically.
- Routes and backend PIDs are recorded in `/var/run/bridge/state.json`; a restarted
  helper cleans up whatever a crashed one left behind.

## Security

- Only root and members of the `admin` group can talk to the helper (`getpeereid`).
- The helper refuses to execute backends that are not owned by root or are writable by others.
- Scripts from config files never run: `PreUp`/`PostUp`/… in WireGuard configs and
  `up`/`down`/`plugin`/`tls-verify`/… in OpenVPN configs are stripped. OpenVPN configs
  must be self-contained (no file references, no `config` includes) when they reach the helper.
- Private keys and passwords never appear in logs; OpenVPN passwords live in the Keychain.

## Network protection

- **Network changes**: when Wi-Fi/Ethernet changes, routes to VPN servers and
  excluded networks follow the new uplink; OpenVPN tunnels reconnect.
- **Kill switch** (per tunnel): while connected, only the VPN, its server, DHCP and
  the local network are reachable (pf anchor `com.apple/bridge`). If the tunnel
  drops, traffic stays blocked until you reconnect or choose "Unblock Internet".
- **IPv6 leak protection**: full tunnels without IPv6 block outgoing IPv6.

## Not yet

Corporate protocols (OpenConnect), Developer ID signing.

## License

MIT, see [LICENSE](LICENSE). Bundled backends keep their own licenses:
amneziawg-go (MIT), OpenVPN (GPL-2.0, built from unmodified upstream source).

# Bridge

[![Support on Boosty](https://img.shields.io/badge/Boosty-support-F15F2C?logo=boosty&logoColor=white)](https://boosty.to/rtm00)
[![Latest release](https://img.shields.io/github/v/release/rtmo0/vpn-tunnel-bridge)](https://github.com/rtmo0/vpn-tunnel-bridge/releases/latest)
![macOS 14+](https://img.shields.io/badge/macOS-14%2B-black?logo=apple)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

**Tunnel Bridge** is a free, open-source VPN client for macOS that lives in the menu bar. It connects **AmneziaWG**, **WireGuard** and **OpenVPN** tunnels from ordinary `.conf` and `.ovpn` files, and it can keep several of them up at once.

Bridge started as a replacement for clients that silently drop newer AmneziaWG settings. It passes every parameter of AmneziaWG 1.0, 1.5 and 2.0 to the backend, and it refuses a config with a key it doesn't understand instead of quietly ignoring it.

It needs no Network Extension, no Apple Developer account and no App Store. A small helper runs the VPN backends with administrator rights, much like Tunnelblick or Shimo do.

## What it can do

| | Feature |
| :-: | --- |
| ✅ | Lives in the menu bar, no Dock icon. The shield shows the state: empty, connecting, a check mark, or the number of connected tunnels |
| ✅ | **AmneziaWG** with every parameter: `Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4` (including ranges), `I1`–`I5`, `HeaderProtectionKey`, `ContentPaddingAddition`, timing options |
| ✅ | **WireGuard** configs as they are |
| ✅ | **OpenVPN 2.7**: username and password, certificates, passphrase-protected keys, one-time codes (static challenge), DNS pushed by the server |
| ✅ | Several tunnels at the same time |
| ✅ | Manage Tunnels window: live status, config summary, built-in config editor, rename, remove |
| ✅ | Split tunnelling: all traffic, only listed networks, or everything except listed networks |
| ✅ | Keep the local network (printers, NAS, AirPlay) off the VPN |
| ✅ | DNS from the config, your own servers, or no change; split DNS for chosen domains |
| ✅ | Kill switch: nothing leaves the Mac outside the tunnel, even if it drops |
| ✅ | IPv6 leak protection for IPv4-only tunnels |
| ✅ | Follows network changes (Wi-Fi to Ethernet, another network) and reconnects OpenVPN |
| ✅ | OpenVPN passwords in the macOS Keychain |
| ✅ | Command-line client `bridge` |
| ✅ | Updates itself from GitHub releases |

## Install on a Mac

### Requirements

- macOS 14 Sonoma or later.
- An administrator account on the Mac (needed once, to install the network helper).
- **Apple Silicon** (M1 or later) for all three protocols. On **Intel** Macs, AmneziaWG and WireGuard work; OpenVPN is currently built for Apple Silicon only.

### 1. Download

1. Open the [latest release](https://github.com/rtmo0/vpn-tunnel-bridge/releases/latest).
2. Under **Assets**, download **`Bridge.zip`**.
3. Open your **Downloads** folder and double-click `Bridge.zip`. You get **`Bridge.app`**.
4. Drag **`Bridge.app`** into **Applications**.

Optional: check the download. The release also contains `Bridge.zip.sha256`. In Terminal:

```bash
cd ~/Downloads
shasum -a 256 Bridge.zip      # must match the text inside Bridge.zip.sha256
```

### 2. Allow it to open the first time

Bridge isn't notarized by Apple: that needs a paid developer account, and Bridge is a free project. So the first time you open it, macOS shows a warning such as *“Bridge” can’t be opened* or *Apple could not verify “Bridge”*. This happens once.

**On macOS 15 Sequoia and later:**

1. Double-click **Bridge** in Applications. When the warning appears, click **Done** (not *Move to Trash*).
2. Open **System Settings → Privacy & Security**.
3. Scroll down to the message about Bridge and click **Open Anyway**.
4. Confirm with **Open Anyway** and your password or Touch ID.

**On macOS 14 Sonoma:** in Applications, **right-click** (or Control-click) **Bridge → Open**, then click **Open** in the dialog.

**Or use Terminal** (works on any version). This removes the “downloaded from the internet” flag from the app:

```bash
xattr -dr com.apple.quarantine /Applications/Bridge.app
open /Applications/Bridge.app
```

### 3. Install the network helper

1. A shield icon appears in the menu bar, at the top right of the screen. Bridge has no Dock icon and no window by default.
2. Click the shield and choose **Install Helper…**.
3. Enter your Mac password when asked.

The helper is a background service (`/Library/PrivilegedHelperTools/com.rtmo0.bridge.helper`). It creates the tunnels, sets routes and DNS, and keeps tunnels running even when the app is closed. Bridge asks to update it after every app update. This also takes one password prompt, and it briefly disconnects your tunnels.

### 4. Add your tunnels

1. Click the shield and choose **Import Tunnel(s) from File…** (⌘O).
2. Pick one or more `.conf` (WireGuard / AmneziaWG) or `.ovpn` (OpenVPN) files.
   - For OpenVPN, certificates and keys that the `.ovpn` points to are copied into Bridge. You can delete the original files afterwards.
   - If the `.ovpn` comes with a login file (`auth-user-pass file.txt`), the username and password go into the Keychain.
3. To connect, click the tunnel's name in the menu. A check mark means it's connected; the line underneath shows uptime and speed.

OpenVPN servers that need a login ask for a username and password the first time. Tick **Remember in Keychain** and you won't be asked again.

### 5. Optional: start at login

Open **System Settings → General → Login Items** and add **Bridge** under *Open at Login*.

### Coming from Shimo, AmneziaVPN or the WireGuard app

- Export your tunnels as `.conf` / `.ovpn` files from the old app and import them into Bridge.
- **Don't run two VPN apps that both send all traffic through themselves at the same time.** The tunnels fight over the default route, and sites stop opening. Disconnect the old app first, or quit it.

## Using Bridge

### The menu

| Item | What it does |
| --- | --- |
| **Status** | Connected tunnel, connecting, inactive, or a helper or kill switch notice |
| Tunnel names | Click to connect or disconnect. ✓ = connected; animated dots = connecting |
| **Disconnect All** | Shown while anything is connected |
| **Import Tunnel(s) from File…** | Add `.conf` / `.ovpn` files |
| **Manage Tunnels…** (⌘,) | The window with details and settings |
| **Update to Bridge x.y…** | Shown when a new release is out |
| **Unblock Internet (Kill Switch)** | Shown when a dropped tunnel's kill switch is blocking traffic |

### Manage Tunnels

Select a tunnel on the left. On the right:

- **Status**: uptime, server, interface, addresses, DNS, last handshake (WireGuard), traffic.
- **Configuration**: what the config says. AmneziaWG parameters are listed under a disclosure triangle. **Edit…** opens the config in a text editor that checks it before saving.
- **Sign-in** (OpenVPN with a login): view or change the saved username and password.
- **Routing**:
  - *As in configuration*: AllowedIPs, or the routes the OpenVPN server pushes.
  - *All traffic*: everything through the VPN.
  - *Only these networks* (split tunnelling): only listed networks use the VPN.
  - *All traffic except these networks*: listed networks go direct.
  - *Keep local networks off the VPN*: 10/8, 172.16/12, 192.168/16 stay on your LAN.
  - *Kill switch*: see below.
- **DNS**:
  - *From configuration*, *Custom* servers, or *Don't change system DNS*.
  - *Only for domains* (split DNS): the VPN's DNS answers only these domains, e.g. `corp.example`. Everything else uses your normal DNS. Use it for corporate VPNs whose internal names only resolve inside the network.

Changes are saved with **Save** (⌘S). If the tunnel is connected, Bridge offers to reconnect it so they take effect. The config file itself is never changed by these settings.

The **+** and **−** buttons at the bottom of the list import and remove tunnels. The page icon opens the logs.

### Kill switch

With **Kill switch** on, while that tunnel is connected, the Mac can reach only the tunnel, the VPN server, DHCP and the local network. If the tunnel drops unexpectedly, traffic **stays blocked** so nothing leaks. To get the internet back, reconnect the tunnel or choose **Unblock Internet (Kill Switch)** in the menu. Disconnecting the tunnel yourself lifts the block.

### Network changes and IPv6

- When you switch Wi-Fi networks or plug in Ethernet, Bridge moves the routes to VPN servers to the new connection. OpenVPN tunnels reconnect by themselves.
- If a tunnel takes all traffic but has no IPv6 address, Bridge blocks outgoing IPv6, so IPv6-enabled sites can't bypass the VPN.

## Updates

Bridge checks GitHub releases at launch and every six hours. You can also choose **Check for Updates…**. When **Update to Bridge x.y…** appears in the menu, click it: Bridge downloads the release, checks its SHA-256 checksum and code signature, replaces itself and restarts; your tunnels stay connected. Afterwards, choose **Update Helper…** once. Updating the helper restarts it, which disconnects the tunnels for a moment: connect them again afterwards.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| macOS won't open Bridge | Step 2 of [Install](#2-allow-it-to-open-the-first-time) |
| “Helper not installed” or “needs an update” | Click the shield → **Install / Update Helper…** |
| Connected, but sites don't open | Another VPN app is also connected: disconnect it. Corporate VPN: internal names may need **DNS → Only for domains** |
| Internal names don't resolve | Manage Tunnels → DNS: set the VPN's DNS server under *Custom* and the company domains under *Only for domains* |
| No internet after a tunnel dropped | The kill switch is on: menu → **Unblock Internet (Kill Switch)** |
| Something else | Logs: menu → Manage Tunnels → page icon, or `/var/log/bridge/helper.log` and `/var/log/bridge/<tunnel>.log` |

When reporting a bug, attach the relevant lines from these logs. They never contain keys or passwords.

## Uninstall

1. Click the shield → **Disconnect All**, then **Quit Bridge**.
2. Remove the helper:
   ```bash
   sudo /Applications/Bridge.app/Contents/Resources/install-helper.sh --uninstall
   ```
3. Move **Bridge** from Applications to the Trash.
4. Optional: delete your saved tunnels in `~/Library/Application Support/Bridge`. In **Keychain Access**, delete the items named *Bridge: …*.

## Command line

Installing the helper also puts `bridge` in `/usr/local/bin`:

```bash
bridge import my-server.conf      # add to the library
bridge list                       # saved tunnels and their state
bridge up my-server               # connect
bridge status                     # handshake, traffic, interface
bridge down my-server             # disconnect (or: bridge down --all)
bridge check file.ovpn            # validate without connecting
```

## How it works

```
Bridge.app / bridge CLI (your user)
        │  JSON over /var/run/bridge/helper.sock (admin users only)
        ▼
bridge-helper (root, launchd)
  ├─ amneziawg-go -f utun   configured over its UAPI socket; Bridge sets addresses,
  │                         split default route (0/1 + 128/1), pinned server route
  ├─ openvpn                driven via its management socket; Bridge answers password
  │                         prompts and is its route-up and dns-updown hook
  ├─ DNS                    System Configuration dynamic store
  └─ pf anchor com.apple/bridge   kill switch and IPv6 leak protection
```

- DNS settings are temporary keys of the helper's session: if the helper dies, macOS removes them automatically. When a VPN's DNS has to apply system-wide, the original values are saved and restored.
- Routes, backend PIDs and firewall state are recorded in `/var/run/bridge`. A restarted helper cleans up whatever a crashed one left behind, and never leaves the Mac without internet.

## Security

- Only root and members of the `admin` group can talk to the helper (checked with `getpeereid`).
- The helper refuses to run backends that aren't owned by root or are writable by others.
- Scripts from config files never run. `PreUp`/`PostUp`/… in WireGuard configs and `up`/`down`/`plugin`/`tls-verify`/… in OpenVPN configs are stripped. OpenVPN configs must be self-contained (no file references, no `config` includes) when they reach the helper.
- Keys and passwords never appear in logs. OpenVPN passwords live in the Keychain.

## Build from source

Requirements: macOS 14+, Xcode command-line tools (Swift 6), Homebrew.

```bash
git clone https://github.com/rtmo0/vpn-tunnel-bridge.git
cd vpn-tunnel-bridge
brew install go openssl@3 lz4 lzo pkgconf
scripts/build-openvpn.sh   # OpenVPN with static OpenSSL, LZ4 and LZO (optional)
scripts/build.sh           # amneziawg-go, CLI, helper → build/Bridge.app
open build/Bridge.app
```

`swift test` runs the unit tests. Pushing a tag such as `v0.4.1` makes GitHub Actions build, test and publish a release, which existing installs pick up as an update.

### Project layout

| Path | Contents |
| --- | --- |
| `Sources/BridgeCore` | Config parsers (wg-quick, OpenVPN), settings, UAPI, helper protocol |
| `Sources/BridgeClient` | Tunnel library, Keychain, connect flow with password prompts |
| `Sources/BridgeApp` | Menu bar app, Manage Tunnels window, updater |
| `Sources/bridge-helper` | Privileged daemon: backends, routes, DNS, firewall, network monitor |
| `Sources/bridge` | Command-line client |
| `scripts/` | Build, OpenVPN build, icon, helper installer |
| `.github/workflows/release.yml` | Release builds |

## Support

Bridge is free and open source. If it keeps you connected, you can support development on [Boosty](https://boosty.to/rtm00). Bug reports and pull requests help a lot too.

## License

MIT, see [LICENSE](LICENSE). Copyright © 2026 Andrey Samarin.

Bundled backends keep their own licenses: [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) (MIT) and [OpenVPN](https://github.com/OpenVPN/openvpn) (GPL-2.0, built from unmodified upstream source).

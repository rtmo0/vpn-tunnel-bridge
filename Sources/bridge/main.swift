import BridgeClient
import BridgeCore
import Foundation

let usage = """
bridge — Tunnel Bridge command-line client

USAGE
  bridge import <file> [--name <name>]       Save a .conf (WireGuard/AmneziaWG) or .ovpn to your library
  bridge import '<link>' [--name <name>]     Save a vless:// / trojan:// / hysteria2:// link (or a file /
                                             subscription with several)
  bridge list                                List saved tunnels and whether they are connected
  bridge up <name | file | link> [--name <n>]  Connect a tunnel
  bridge down <name> | --all                 Disconnect
  bridge status [name]                       Live status
  bridge check <name | file>                 Validate a config and show what will be applied
  bridge remove <name>                       Delete a saved tunnel (and its saved passwords)
  bridge forget <name>                       Delete saved passwords of a tunnel

  bridge profile import <file | happ://…>    Import a routing profile (routing.json) and its geo files
  bridge profile list                        Imported routing profiles and the tunnels using them
  bridge profile use <tunnel> <profile|none> Route a VLESS / Trojan / Hysteria 2 tunnel by a profile
  bridge profile update <profile>            Download the profile's geo files again
  bridge profile remove <profile>            Delete a routing profile

Library: ~/Library/Application Support/Bridge/Tunnels
"""

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

var arguments = Array(CommandLine.arguments.dropFirst())

func takeOption(_ name: String) throws -> String? {
    guard let index = arguments.firstIndex(of: name) else { return nil }
    guard index + 1 < arguments.count else { throw CLIError("\(name) needs a value") }
    let value = arguments[index + 1]
    arguments.removeSubrange(index...(index + 1))
    return value
}

func takeFlag(_ name: String) -> Bool {
    guard let index = arguments.firstIndex(of: name) else { return false }
    arguments.remove(at: index)
    return true
}

/// A saved tunnel name or a path to a config file.
func resolve(_ reference: String, nameOverride: String?) throws -> (name: String, loaded: TunnelLibrary.Loaded) {
    if ProxyLink.isLink(reference) {
        let loaded = try TunnelLibrary.loadedLink(reference, fallbackName: "tunnel")
        return (nameOverride.map(TunnelName.sanitized) ?? loaded.suggestedName, loaded)
    }
    let path = (reference as NSString).expandingTildeInPath
    var isDirectory: ObjCBool = false
    if FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue {
        let loaded = try TunnelLibrary.read(fileAt: URL(fileURLWithPath: path))
        return (nameOverride.map(TunnelName.sanitized) ?? loaded.suggestedName, loaded)
    }
    guard TunnelLibrary.find(reference) != nil else {
        throw CLIError("No saved tunnel or file named '\(reference)'. See 'bridge list'.")
    }
    let saved = try TunnelLibrary.load(reference)
    return (nameOverride ?? reference,
            TunnelLibrary.Loaded(suggestedName: reference, kind: saved.kind, text: saved.text, embedded: .init(), warnings: []))
}

// MARK: Prompts

func prompt(_ text: String) -> String {
    print(text, terminator: "")
    fflush(stdout)
    return readLine() ?? ""
}

func promptSecret(_ text: String) -> String {
    guard let value = getpass(text) else { return "" }
    return String(cString: value)
}

func askYesNo(_ text: String) -> Bool {
    let answer = prompt("\(text) [Y/n] ").lowercased()
    return answer.isEmpty || answer.hasPrefix("y")
}

func ask(_ secret: SecretPrompt) -> SecretAnswer? {
    switch secret {
    case let .usernamePassword(tunnel, username, retry):
        if retry { print("Authentication failed for '\(tunnel)'.") }
        var user = prompt("Username\(username.map { " [\($0)]" } ?? ""): ")
        if user.isEmpty { user = username ?? "" }
        guard !user.isEmpty else { return nil }
        let pass = promptSecret("Password: ")
        return SecretAnswer(username: user, secret: pass, remember: askYesNo("Save in Keychain?"))
    case let .keyPassphrase(tunnel, retry):
        if retry { print("Wrong passphrase.") }
        let pass = promptSecret("Private key passphrase for '\(tunnel)': ")
        guard !pass.isEmpty else { return nil }
        return SecretAnswer(secret: pass, remember: askYesNo("Save in Keychain?"))
    case let .challenge(_, text, echo):
        let value = echo ? prompt("\(text): ") : promptSecret("\(text): ")
        return value.isEmpty ? nil : SecretAnswer(secret: value, remember: false)
    }
}

// MARK: Formatting

func ago(_ date: Date?) -> String {
    guard let date else { return "never" }
    let seconds = max(0, Int(Date().timeIntervalSince(date)))
    if seconds < 60 { return "\(seconds)s ago" }
    if seconds < 3600 { return "\(seconds / 60)m \(seconds % 60)s ago" }
    return "\(seconds / 3600)h \(seconds % 3600 / 60)m ago"
}

func bytes(_ count: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .binary)
}

func printStatus(_ s: TunnelStatus) {
    print("\(s.name): \(s.state)")
    print("  protocol:   \(s.kind.displayName)")
    print("  interface:  \(s.interface.isEmpty ? "-" : s.interface) (pid \(s.pid))")
    if let server = s.server { print("  server:     \(server)") }
    if !s.addresses.isEmpty { print("  addresses:  \(s.addresses.joined(separator: ", "))") }
    if !s.dnsServers.isEmpty { print("  dns:        \(s.dnsServers.joined(separator: ", "))") }
    print("  routing:    \(s.fullTunnel ? "all traffic" : "selected networks")")
    if s.kind.usesXray {
        print("  last check: \(ago(s.lastHandshake))")
    } else if s.kind != .openvpn {
        print("  handshake:  \(ago(s.lastHandshake))")
    }
    print("  traffic:    received \(bytes(s.rxBytes)), sent \(bytes(s.txBytes))")
    for warning in s.warnings { print("  note: \(warning)") }
}

func describe(_ loaded: TunnelLibrary.Loaded) throws {
    print("protocol:   \(loaded.kind.displayName)")
    switch loaded.kind {
    case .amneziawg, .wireguard:
        let config = try TunnelConfig.parse(loaded.text)
        print("addresses:  \(config.addresses.map(\.description).joined(separator: ", "))")
        if !config.dnsServers.isEmpty || !config.dnsSearchDomains.isEmpty {
            print("dns:        \((config.dnsServers.map(\.description) + config.dnsSearchDomains).joined(separator: ", "))")
        }
        print("mtu:        \(config.mtu.map(String.init) ?? "auto")")
        print("routing:    \(config.isFullTunnel ? "all traffic" : "selected networks")")
        if !config.deviceParameters.isEmpty {
            print("parameters passed to the backend:")
            for p in config.deviceParameters {
                let shown = p.isSecret ? "(key, hidden)"
                    : p.value.count > 48 ? "\(p.value.prefix(40))… (\(p.value.count) chars)" : p.value
                print("  \(p.name.padding(toLength: 24, withPad: " ", startingAt: 0)) \(shown)")
            }
        }
        for peer in config.peers {
            print("peer \(peer.publicKey.prefix(8))…  \(peer.endpoint?.description ?? "no endpoint")")
            print("  allowed:   \(peer.allowedIPs.map(\.description).joined(separator: ", "))")
        }
        for warning in config.warnings { print("note: \(warning)") }
    case .openvpn:
        let config = try OpenVPNConfig.parse(loaded.text)
        print("servers:    \(config.remotes.joined(separator: ", "))")
        print("routing:    \(config.redirectsGateway ? "all traffic" : "as pushed by the server")")
        print("login:      \(config.needsUsernamePassword ? "username + password" : "certificate only")")
        if let challenge = config.staticChallenge { print("challenge:  \(challenge.text)") }
        if config.hasEncryptedPrivateKey { print("key:        passphrase-protected") }
        let prepared = try config.prepared(tunnel: "check", managementSocket: "/dev/null", eventCommand: "true")
        for warning in prepared.warnings { print("note: \(warning)") }
    case .vless, .trojan, .hysteria2:
        let link = try ProxyLink.parse(loaded.text)
        print("server:     \(link.endpoint)")
        for row in link.summary {
            let label = row.name.lowercased() + ":"
            print("\(label.padding(toLength: max(11, label.count), withPad: " ", startingAt: 0)) \(row.value)")
        }
        print("dns:        \(ProxyLink.defaultDNS.joined(separator: ", ")) (default, change in settings)")
        print("routing:    all traffic; IPv6 too if the server reaches it")
    }
}

// MARK: Commands

func run() throws {
    guard let command = arguments.first else {
        print(usage)
        return
    }
    arguments.removeFirst()

    switch command {
    case "import":
        let name = try takeOption("--name")
        guard let file = arguments.first else { throw CLIError("Usage: bridge import <file | link> [--name <name>]") }
        let saved: [SavedTunnel]
        if ProxyLink.isLink(file), let name {
            let link = try ProxyLink.parse(file)
            saved = [try TunnelLibrary.save(ProxyLink.normalized(file), kind: link.kind, as: TunnelName.sanitized(name))]
        } else if ProxyLink.isLink(file) {
            let result = try TunnelLibrary.importLinks(file)
            for error in result.errors { print("! \(error)") }
            saved = result.saved
        } else {
            saved = try TunnelLibrary.importFile(at: URL(fileURLWithPath: (file as NSString).expandingTildeInPath),
                                                 as: name)
        }
        for tunnel in saved {
            print("Saved '\(tunnel.name)' (\(tunnel.kind.displayName)). Connect with: bridge up \(tunnel.name)")
        }

    case "profile":
        guard let sub = arguments.first else { throw CLIError("Usage: bridge profile import | list | use | update | remove") }
        arguments.removeFirst()
        switch sub {
        case "import":
            guard let source = arguments.first else { throw CLIError("Usage: bridge profile import <file | happ://…>") }
            let path = (source as NSString).expandingTildeInPath
            let text = FileManager.default.fileExists(atPath: path) ? try String(contentsOfFile: path, encoding: .utf8) : source
            let name = try RoutingProfiles.importProfile(text)
            print("Imported routing profile '\(name)'. Use it with: bridge profile use <tunnel> \(name)")
        case "list":
            let profiles = RoutingProfiles.list()
            if profiles.isEmpty { print("No routing profiles. Import one with: bridge profile import <file>") }
            let users = TunnelLibrary.list().map { ($0.name, TunnelLibrary.settings(for: $0.name).routingProfile) }
            for name in profiles {
                let profile = try? RoutingProfiles.load(name)
                let used = users.filter { $0.1 == name }.map(\.0)
                print("\(name.padding(toLength: 24, withPad: " ", startingAt: 0)) "
                    + (profile.map { $0.globalProxy ? "default: proxy" : "default: direct" } ?? "unreadable")
                    + (used.isEmpty ? "" : "   used by \(used.joined(separator: ", "))"))
            }
        case "use":
            guard arguments.count >= 2 else { throw CLIError("Usage: bridge profile use <tunnel> <profile | none>") }
            let tunnel = arguments[0], profile = arguments[1]
            guard let saved = TunnelLibrary.find(tunnel) else { throw CLIError("No saved tunnel named '\(tunnel)'") }
            var settings = TunnelLibrary.settings(for: tunnel)
            if profile == "none" {
                settings.routingProfile = nil
            } else {
                guard saved.kind.usesXray else {
                    throw CLIError("Routing profiles work with VLESS, Trojan and Hysteria 2 tunnels only")
                }
                guard RoutingProfiles.list().contains(profile) else { throw CLIError("No routing profile named '\(profile)'") }
                settings.routingProfile = profile
            }
            try TunnelLibrary.saveSettings(settings, for: tunnel)
            print(profile == "none" ? "'\(tunnel)' no longer uses a routing profile."
                  : "'\(tunnel)' now uses routing profile '\(profile)'. Reconnect it to apply.")
        case "update":
            guard let name = arguments.first else { throw CLIError("Usage: bridge profile update <profile>") }
            try RoutingProfiles.update(name)
            print("Updated the geo files of '\(name)'.")
        case "remove":
            guard let name = arguments.first else { throw CLIError("Usage: bridge profile remove <profile>") }
            try RoutingProfiles.remove(name)
            print("Removed routing profile '\(name)'.")
        default:
            throw CLIError("Unknown profile command '\(sub)'")
        }

    case "list":
        let saved = TunnelLibrary.list()
        let active = (try? HelperClient.statuses()) ?? []
        if saved.isEmpty && active.isEmpty { print("No tunnels yet. Add one with: bridge import <file>") }
        let names = Set(saved.map(\.name)).union(active.map(\.name)).sorted()
        for name in names {
            let kind = saved.first { $0.name == name }?.kind ?? active.first { $0.name == name }?.kind
            let state = active.first { $0.name == name }?.state ?? "Disconnected"
            print("\(name.padding(toLength: 24, withPad: " ", startingAt: 0)) "
                + "\((kind?.displayName ?? "").padding(toLength: 11, withPad: " ", startingAt: 0)) \(state)")
        }

    case "up":
        let override = try takeOption("--name")
        guard let reference = arguments.first else { throw CLIError("Usage: bridge up <name | file>") }
        let (name, loaded) = try resolve(reference, nameOverride: override)
        guard TunnelName.isValid(name) else { throw CLIError("'\(name)' is not a valid tunnel name") }
        print("Connecting '\(name)' (\(loaded.kind.displayName))…")
        var status = try Connector.connect(name: name, text: loaded.text, kind: loaded.kind,
                                           embedded: loaded.embedded, ask: ask)
        let deadline = Date().addingTimeInterval(6)
        while !status.connected && Date() < deadline {
            usleep(500_000)
            if let fresh = (try? HelperClient.statuses())?.first(where: { $0.name == name }) { status = fresh }
        }
        printStatus(status)
        if !status.connected {
            print("\nNot connected yet. Details: /var/log/bridge/\(name).log")
        }

    case "down":
        if takeFlag("--all") {
            try HelperClient.call(HelperRequest(command: .downAll))
            print("All tunnels disconnected.")
        } else {
            guard let name = arguments.first else { throw CLIError("Usage: bridge down <name> | --all") }
            try HelperClient.disconnect(name)
            print("'\(name)' disconnected.")
        }

    case "status":
        let name = arguments.first
        let tunnels = try HelperClient.statuses().filter { name == nil || $0.name == name }
        if tunnels.isEmpty { print(name.map { "'\($0)' is not connected." } ?? "No tunnels connected.") }
        for (index, status) in tunnels.enumerated() {
            if index > 0 { print("") }
            printStatus(status)
        }

    case "check":
        guard let reference = arguments.first else { throw CLIError("Usage: bridge check <name | file>") }
        try describe(try resolve(reference, nameOverride: nil).loaded)
        print("\nConfig is valid.")

    case "remove":
        guard let name = arguments.first else { throw CLIError("Usage: bridge remove <name>") }
        try TunnelLibrary.remove(name)
        print("Removed '\(name)'.")

    case "forget":
        guard let name = arguments.first else { throw CLIError("Usage: bridge forget <name>") }
        Keychain.deleteAll(for: name)
        print("Saved passwords of '\(name)' deleted.")

    case "-h", "--help", "help":
        print(usage)

    default:
        throw CLIError("Unknown command '\(command)'.\n\n\(usage)")
    }
}

do {
    try run()
} catch {
    FileHandle.standardError.write("bridge: \(error)\n".data(using: .utf8)!)
    exit(1)
}

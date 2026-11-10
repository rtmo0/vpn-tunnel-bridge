import BridgeCore
import Foundation

let usage = """
bridge — Tunnel Bridge command-line client

USAGE
  bridge import <file.conf> [--name <name>]   Save a config to your tunnel library
  bridge list                                  List saved tunnels and whether they are connected
  bridge up <name | file.conf> [--name <n>]   Connect a tunnel
  bridge down <name> | --all                  Disconnect
  bridge status [name]                        Live status: handshake, traffic, interface
  bridge check <name | file.conf>             Validate a config and show what will be applied
  bridge remove <name>                        Delete a saved tunnel

Supported: AmneziaWG (1.0, 1.5, 2.0 parameters) and plain WireGuard.
Library: ~/Library/Application Support/Bridge/Tunnels
"""

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

// MARK: - Argument helpers

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

/// Accepts either a saved tunnel name or a path to a .conf file.
func resolveConfig(_ reference: String, nameOverride: String?) throws -> (name: String, text: String) {
    let path = (reference as NSString).expandingTildeInPath
    var isDirectory: ObjCBool = false
    if FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue {
        let text = try String(contentsOfFile: path, encoding: .utf8)
        let name = nameOverride ?? URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
        return (name, text)
    }
    guard TunnelLibrary.names().contains(reference) else {
        throw CLIError("No saved tunnel or file named '\(reference)'. See 'bridge list'.")
    }
    return (nameOverride ?? reference, try TunnelLibrary.load(reference))
}

func validName(_ name: String) throws -> String {
    guard TunnelName.isValid(name) else {
        throw CLIError("'\(name)' is not a valid tunnel name: use letters, digits, '-', '_' and '.' (max 40).")
    }
    return name
}

func parse(_ text: String) throws -> TunnelConfig {
    do {
        return try TunnelConfig.parse(text)
    } catch let error as ConfigError {
        throw CLIError("Invalid config: \(error)")
    }
}

// MARK: - Formatting

func ago(_ date: Date?) -> String {
    guard let date else { return "never" }
    let seconds = Int(Date().timeIntervalSince(date))
    if seconds < 60 { return "\(seconds)s ago" }
    if seconds < 3600 { return "\(seconds / 60)m \(seconds % 60)s ago" }
    return "\(seconds / 3600)h \(seconds % 3600 / 60)m ago"
}

func bytes(_ count: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .binary)
}

func health(_ status: TunnelStatus) -> String {
    guard let last = status.lastHandshake else { return "waiting for handshake" }
    // WireGuard re-handshakes every 2 minutes while traffic flows.
    return Date().timeIntervalSince(last) < 180 ? "connected" : "stale (no recent handshake)"
}

func printStatus(_ status: TunnelStatus) {
    print("\(status.name): \(health(status))")
    print("  protocol:   \(status.amnezia ? "AmneziaWG" : "WireGuard")")
    print("  interface:  \(status.interface) (pid \(status.pid)), up \(ago(status.startedAt).replacingOccurrences(of: " ago", with: ""))")
    print("  addresses:  \(status.addresses.joined(separator: ", "))")
    if !status.dnsServers.isEmpty { print("  dns:        \(status.dnsServers.joined(separator: ", "))") }
    print("  routing:    \(status.fullTunnel ? "all traffic" : "selected networks")")
    for peer in status.peers {
        print("  peer \(peer.publicKey.prefix(8))…  \(peer.endpoint ?? "no endpoint")")
        print("    handshake \(ago(peer.lastHandshake)), received \(bytes(peer.rxBytes)), sent \(bytes(peer.txBytes))")
    }
    for warning in status.warnings { print("  note: \(warning)") }
}

func describe(_ config: TunnelConfig) {
    print("protocol:   \(config.usesAmneziaObfuscation ? "AmneziaWG" : "WireGuard")")
    print("addresses:  \(config.addresses.map(\.description).joined(separator: ", "))")
    if !config.dnsServers.isEmpty || !config.dnsSearchDomains.isEmpty {
        print("dns:        \((config.dnsServers.map(\.description) + config.dnsSearchDomains).joined(separator: ", "))")
    }
    print("mtu:        \(config.mtu.map(String.init) ?? "auto")")
    print("routing:    \(config.isFullTunnel ? "all traffic" : "selected networks")")
    if !config.deviceParameters.isEmpty {
        print("parameters passed to the backend:")
        for p in config.deviceParameters {
            let shown: String
            if p.isSecret {
                shown = "(key, hidden)"
            } else if p.value.count > 48 {
                shown = "\(p.value.prefix(40))… (\(p.value.count) chars)"
            } else {
                shown = p.value
            }
            print("  \(p.name.padding(toLength: 24, withPad: " ", startingAt: 0)) \(shown)")
        }
    }
    for peer in config.peers {
        print("peer \(peer.publicKey.prefix(8))…  \(peer.endpoint?.description ?? "no endpoint")")
        print("  allowed:   \(peer.allowedIPs.map(\.description).joined(separator: ", "))")
        if let keepalive = peer.persistentKeepalive { print("  keepalive: \(keepalive)s") }
        if peer.presharedKey != nil { print("  preshared key: yes") }
    }
    for warning in config.warnings { print("note: \(warning)") }
}

func request(_ request: HelperRequest, timeout: Int = 60) throws -> HelperResponse {
    let response = try HelperClient.send(request, timeout: timeout)
    guard response.ok else { throw CLIError(response.error ?? "helper reported an unknown error") }
    return response
}

// MARK: - Commands

func run() throws {
    guard let command = arguments.first else {
        print(usage)
        return
    }
    arguments.removeFirst()

    switch command {
    case "import":
        let name = try takeOption("--name")
        guard let file = arguments.first else { throw CLIError("Usage: bridge import <file.conf> [--name <name>]") }
        let path = (file as NSString).expandingTildeInPath
        let text = try String(contentsOfFile: path, encoding: .utf8)
        let config = try parse(text)
        let tunnelName = try validName(name ?? URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent)
        try TunnelLibrary.save(text, as: tunnelName)
        print("Saved '\(tunnelName)' (\(config.usesAmneziaObfuscation ? "AmneziaWG" : "WireGuard")).")
        print("Connect with: bridge up \(tunnelName)")

    case "list":
        let saved = TunnelLibrary.names()
        let active = (try? HelperClient.send(HelperRequest(command: .status), timeout: 5))?.tunnels ?? []
        let activeNames = Set(active.map(\.name))
        if saved.isEmpty && active.isEmpty {
            print("No tunnels yet. Add one with: bridge import <file.conf>")
        }
        for name in Set(saved).union(activeNames).sorted() {
            let state = active.first { $0.name == name }.map(health) ?? "disconnected"
            print("\(name.padding(toLength: 24, withPad: " ", startingAt: 0)) \(state)")
        }

    case "up":
        let name = try takeOption("--name")
        guard let reference = arguments.first else { throw CLIError("Usage: bridge up <name | file.conf>") }
        let resolved = try resolveConfig(reference, nameOverride: name)
        _ = try parse(resolved.text)
        let tunnelName = try validName(resolved.name)
        print("Connecting '\(tunnelName)'…")
        let response = try request(HelperRequest(command: .up, name: tunnelName, config: resolved.text))

        // Give the first handshake a moment so the user sees a meaningful state.
        var status = response.tunnels?.first
        let deadline = Date().addingTimeInterval(6)
        while status?.lastHandshake == nil && Date() < deadline {
            usleep(500_000)
            status = (try? request(HelperRequest(command: .status, name: tunnelName), timeout: 5))?.tunnels?.first
        }
        if let status { printStatus(status) }
        if status?.lastHandshake == nil {
            print("\nNo handshake yet. If it stays like this, check the server and see /var/log/bridge/\(tunnelName).log")
        }

    case "down":
        if takeFlag("--all") {
            _ = try request(HelperRequest(command: .downAll))
            print("All tunnels disconnected.")
        } else {
            guard let name = arguments.first else { throw CLIError("Usage: bridge down <name> | --all") }
            _ = try request(HelperRequest(command: .down, name: name))
            print("'\(name)' disconnected.")
        }

    case "status":
        let name = arguments.first
        let tunnels = try request(HelperRequest(command: .status, name: name), timeout: 10).tunnels ?? []
        if tunnels.isEmpty {
            print(name.map { "'\($0)' is not connected." } ?? "No tunnels connected.")
        }
        for (index, status) in tunnels.enumerated() {
            if index > 0 { print("") }
            printStatus(status)
        }

    case "check":
        guard let reference = arguments.first else { throw CLIError("Usage: bridge check <name | file.conf>") }
        let resolved = try resolveConfig(reference, nameOverride: nil)
        describe(try parse(resolved.text))
        print("\nConfig is valid.")

    case "remove":
        guard let name = arguments.first else { throw CLIError("Usage: bridge remove <name>") }
        guard TunnelLibrary.names().contains(name) else { throw CLIError("No saved tunnel named '\(name)'.") }
        try TunnelLibrary.remove(name)
        print("Removed '\(name)'.")

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

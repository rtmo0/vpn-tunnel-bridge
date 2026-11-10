import Foundation

/// Kill switch and IPv6 leak protection with the macOS packet filter (pf).
///
/// Rules live in the anchor `com.apple/bridge`, which the stock /etc/pf.conf
/// evaluates (`anchor "com.apple/*"`). pf is enabled with a reference token
/// (`pfctl -E`) and released again (`pfctl -X`), so other pf users are unaffected.
final class Firewall {
    static let anchor = "com.apple/bridge"
    private static let pfctl = "/sbin/pfctl"
    private static let tokenPath = "/var/run/bridge/pf.token"

    struct Rules: Equatable {
        /// Interfaces of Bridge tunnels that are up.
        var tunnelInterfaces: [String] = []
        /// VPN servers that must stay reachable outside the tunnel.
        var servers: [String] = []
        var killSwitch = false
        /// Drop IPv6 that would bypass a full tunnel without IPv6.
        var blockIPv6 = false

        var isEmpty: Bool { !killSwitch && !blockIPv6 }
    }

    private var current: Rules?
    private var token: String?

    func apply(_ rules: Rules) {
        if rules.isEmpty {
            clear()
            return
        }
        guard rules != current else { return }
        let text = Self.render(rules)
        let load = runWithInput(Self.pfctl, ["-a", Self.anchor, "-f", "-"], input: text)
        guard load.status == 0 else {
            log("! pf rules rejected: \(load.output.trimmingCharacters(in: .whitespacesAndNewlines))")
            return
        }
        enable()
        current = rules
        var what: [String] = []
        if rules.killSwitch { what.append("kill switch") }
        if rules.blockIPv6 && !rules.killSwitch { what.append("IPv6 leak protection") }
        log("  firewall: \(what.joined(separator: " + ")) on (tunnels: \(rules.tunnelInterfaces.joined(separator: ", ")))")
    }

    func clear() {
        guard current != nil || token != nil else { return }
        run(Self.pfctl, ["-a", Self.anchor, "-F", "all"])
        release()
        current = nil
        log("  firewall rules removed")
    }

    /// Removes rules a crashed helper left behind, so a restart never locks the Mac out.
    func recover() {
        token = (try? String(contentsOfFile: Self.tokenPath, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        run(Self.pfctl, ["-a", Self.anchor, "-F", "all"])
        if token != nil { log("removing firewall rules left by a previous run") }
        release()
    }

    // MARK: Rules

    static func render(_ r: Rules) -> String {
        var lines = ["pass quick on lo0 all"]
        // Neighbour discovery and router advertisements keep the local link working.
        lines.append("pass out quick inet6 proto ipv6-icmp to { fe80::/10, ff02::/16 }")
        for interface in r.tunnelInterfaces {
            lines.append("pass out quick on \(interface) all")
        }
        if r.killSwitch {
            lines.append("pass out quick inet proto udp from any port 68 to any port 67")
            lines.append("pass out quick inet6 proto udp from any port 546 to any port 547")
            lines.append("pass out quick inet to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, "
                + "224.0.0.0/4, 255.255.255.255 }")
            for server in r.servers {
                lines.append("pass out quick to \(server)")
            }
            lines.append("block drop out quick all")
        } else if r.blockIPv6 {
            lines.append("block drop out quick inet6 all")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    // MARK: pf

    private func enable() {
        guard token == nil else { return }
        let result = run(Self.pfctl, ["-E"])
        // "Token : 1234567890"
        for line in result.output.split(separator: "\n") where line.contains("Token") {
            token = line.split(separator: ":").last.map { $0.trimmingCharacters(in: .whitespaces) }
        }
        if let token {
            try? token.write(toFile: Self.tokenPath, atomically: true, encoding: .utf8)
        } else {
            log("! could not enable pf: \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }

    private func release() {
        if let token { run(Self.pfctl, ["-X", token]) }
        token = nil
        try? FileManager.default.removeItem(atPath: Self.tokenPath)
    }

    private func runWithInput(_ path: String, _ args: [String], input: String) -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        let stdin = Pipe(), out = Pipe()
        process.standardInput = stdin
        process.standardOutput = out
        process.standardError = out
        do { try process.run() } catch { return CommandResult(status: -1, output: "\(error)") }
        stdin.fileHandleForWriting.write(Data(input.utf8))
        try? stdin.fileHandleForWriting.close()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        // pfctl prints harmless "ALTQ" notices; only the exit status matters.
        return CommandResult(status: process.terminationStatus, output: String(decoding: data, as: UTF8.self))
    }
}

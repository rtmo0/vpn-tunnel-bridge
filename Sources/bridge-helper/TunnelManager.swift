import BridgeCore
import Foundation

/// Persisted so a restarted helper can clean up after a crash.
struct PersistedTunnel: Codable {
    var name: String
    var pid: Int32
    var backendPath: String
    var interface: String
    var routes: [RouteEntry]
}

final class ActiveTunnel {
    let name: String
    let config: TunnelConfig
    let startedAt = Date()
    var backend: AmneziaBackend?
    var routes: [RouteEntry] = []
    var dnsApplied = false
    var warnings: [String]

    init(name: String, config: TunnelConfig) {
        self.name = name
        self.config = config
        self.warnings = config.warnings
    }
}

/// Owns all tunnels. Every method must run on `queue`.
final class TunnelManager {
    let queue = DispatchQueue(label: "com.rtmo0.bridge.helper.manager")
    private var tunnels: [String: ActiveTunnel] = [:]
    private let dns = DNSManager()
    private let statePath = "\(AmneziaBackend.runDirectory)/state.json"

    // MARK: Requests

    func handle(_ request: HelperRequest) -> HelperResponse {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            switch request.command {
            case .ping:
                return HelperResponse(ok: true)
            case .status:
                return HelperResponse(ok: true, tunnels: try statuses(filter: request.name))
            case .up:
                guard let name = request.name, TunnelName.isValid(name) else {
                    return .failure("Invalid tunnel name")
                }
                guard let text = request.config else { return .failure("No configuration supplied") }
                let status = try up(name: name, configText: text)
                return HelperResponse(ok: true, tunnels: [status])
            case .down:
                guard let name = request.name else { return .failure("No tunnel name") }
                try down(name: name)
                return HelperResponse(ok: true)
            case .downAll:
                downAll()
                return HelperResponse(ok: true)
            }
        } catch {
            return .failure("\(error)")
        }
    }

    // MARK: Up

    private func up(name: String, configText: String) throws -> TunnelStatus {
        guard tunnels[name] == nil else { throw HelperError("Tunnel '\(name)' is already connected") }
        let config: TunnelConfig
        do {
            config = try TunnelConfig.parse(configText)
        } catch {
            throw HelperError("Invalid configuration: \(error)")
        }
        if config.isFullTunnel, let other = tunnels.values.first(where: { $0.config.isFullTunnel }) {
            throw HelperError("'\(other.name)' already routes all traffic. Disconnect it first.")
        }

        log("up '\(name)'\(config.usesAmneziaObfuscation ? " (AmneziaWG)" : " (WireGuard)")")
        let tunnel = ActiveTunnel(name: name, config: config)
        tunnels[name] = tunnel

        do {
            // Resolve endpoints before touching any routes.
            var resolved: [String: Resolver.Resolved] = [:]
            for peer in config.peers {
                if let endpoint = peer.endpoint { resolved[peer.publicKey] = try Resolver.resolve(endpoint) }
            }

            // Pin the route to each server *before* the tunnel routes capture it.
            let allAllowed = config.peers.flatMap(\.allowedIPs)
            var uplinkInterface: String?
            for (_, endpoint) in resolved {
                let ip = endpoint.address
                guard let current = Routes.lookup("\(ip)", ipv6: ip.isIPv6) else {
                    throw HelperError("No route to server \(ip). Is the network up?")
                }
                uplinkInterface = uplinkInterface ?? current.interface
                if allAllowed.contains(where: { $0.contains(ip) }) {
                    let pin = RouteEntry(destination: "\(ip)", ipv6: ip.isIPv6,
                                         gateway: current.gateway, interface: current.gateway == nil ? current.interface : nil)
                    if try Routes.add(pin) { tunnel.routes.append(pin) }
                }
            }
            saveState()

            let backend = try AmneziaBackend.start(tunnel: name) { [weak self] pid in
                self?.queue.async { self?.backendExited(name: name, pid: pid) }
            }
            tunnel.backend = backend
            saveState()

            try backend.configure(config, endpoints: resolved.mapValues(\.uapiValue))

            let mtu = config.mtu ?? defaultMTU(uplink: uplinkInterface)
            try Interface.configure(backend.interface, addresses: config.addresses, mtu: mtu)

            var seen = Set<RouteEntry>()
            for network in allAllowed {
                for entry in Routes.tunnelRoutes(for: network, interface: backend.interface) where !seen.contains(entry) {
                    seen.insert(entry)
                    do {
                        if try Routes.add(entry) { tunnel.routes.append(entry) }
                    } catch where entry.ipv6 {
                        tunnel.warnings.append("IPv6 route \(entry.destination) could not be added; "
                            + "IPv6 traffic may bypass the tunnel.")
                    }
                }
            }
            saveState()

            if let warning = dns.apply(tunnel: name, interface: backend.interface, config: config) {
                tunnel.warnings.append(warning)
            }
            tunnel.dnsApplied = !config.dnsServers.isEmpty
            log("up '\(name)' done on \(backend.interface)")
            return try status(of: tunnel)
        } catch {
            log("up '\(name)' failed: \(error)")
            teardown(tunnel)
            tunnels[name] = nil
            saveState()
            throw error
        }
    }

    private func defaultMTU(uplink: String?) -> Int {
        let base = uplink.flatMap(Interface.mtu(of:))
            ?? Routes.lookup("default", ipv6: false)?.interface.flatMap(Interface.mtu(of:))
            ?? 1500
        return max(1280, base - 80)
    }

    // MARK: Down

    private func down(name: String) throws {
        guard let tunnel = tunnels[name] else { throw HelperError("Tunnel '\(name)' is not connected") }
        log("down '\(name)'")
        teardown(tunnel)
        tunnels[name] = nil
        saveState()
    }

    func downAll() {
        for tunnel in tunnels.values {
            log("down '\(tunnel.name)'")
            teardown(tunnel)
        }
        tunnels.removeAll()
        saveState()
    }

    private func teardown(_ tunnel: ActiveTunnel) {
        dns.remove(tunnel: tunnel.name)
        for route in tunnel.routes.reversed() { Routes.delete(route) }
        tunnel.routes.removeAll()
        tunnel.backend?.stop()
        unlink("\(AmneziaBackend.runDirectory)/\(tunnel.name).ifname")
    }

    private func backendExited(name: String, pid: Int32) {
        guard let tunnel = tunnels[name], tunnel.backend?.pid == pid else { return }
        log("backend of '\(name)' (pid \(pid)) exited unexpectedly, cleaning up")
        teardown(tunnel)
        tunnels[name] = nil
        saveState()
    }

    // MARK: Status

    private func statuses(filter: String?) throws -> [TunnelStatus] {
        try tunnels.values
            .filter { filter == nil || $0.name == filter }
            .sorted { $0.name < $1.name }
            .map(status(of:))
    }

    private func status(of tunnel: ActiveTunnel) throws -> TunnelStatus {
        guard let backend = tunnel.backend else { throw HelperError("Tunnel '\(tunnel.name)' has no backend") }
        let device = (try? backend.status()) ?? UAPI.DeviceStatus()
        return TunnelStatus(
            name: tunnel.name,
            interface: backend.interface,
            pid: backend.pid,
            startedAt: tunnel.startedAt,
            addresses: tunnel.config.addresses.map(\.description),
            dnsServers: tunnel.config.dnsServers.map(\.description),
            fullTunnel: tunnel.config.isFullTunnel,
            amnezia: tunnel.config.usesAmneziaObfuscation,
            peers: device.peers.map {
                TunnelStatus.Peer(publicKey: $0.publicKey, endpoint: $0.endpoint,
                                  lastHandshake: $0.lastHandshake, rxBytes: $0.rxBytes, txBytes: $0.txBytes)
            },
            warnings: tunnel.warnings)
    }

    // MARK: Crash recovery

    private func saveState() {
        let entries = tunnels.values.map {
            PersistedTunnel(name: $0.name, pid: $0.backend?.pid ?? 0, backendPath: AmneziaBackend.executablePath,
                            interface: $0.backend?.interface ?? "", routes: $0.routes)
        }
        do {
            let data = try JSONEncoder.bridge.encode(entries)
            try data.write(to: URL(fileURLWithPath: statePath), options: .atomic)
        } catch {
            log("! could not save state: \(error)")
        }
    }

    /// Removes leftovers of a previous helper instance (crash, kill -9, upgrade).
    func recoverFromPreviousRun() {
        guard let data = FileManager.default.contents(atPath: statePath),
              let entries = try? JSONDecoder.bridge.decode([PersistedTunnel].self, from: data),
              !entries.isEmpty else { return }
        log("cleaning up \(entries.count) tunnel(s) left by a previous run")
        for entry in entries {
            if entry.pid > 0, executablePath(of: entry.pid) == entry.backendPath {
                terminate(pid: entry.pid)
                log("  stopped stale backend pid \(entry.pid) of '\(entry.name)'")
            }
            for route in entry.routes.reversed() { Routes.delete(route) }
        }
        try? FileManager.default.removeItem(atPath: statePath)
    }
}

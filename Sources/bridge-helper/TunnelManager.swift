import BridgeCore
import Foundation

protocol TunnelBackend: AnyObject {
    var pid: Int32 { get }
    var isRunning: Bool { get }
    var interface: String { get }
    func stop()
}

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
    let kind: TunnelKind
    let wireGuard: TunnelConfig?
    let openVPN: OpenVPNConfig?
    let startedAt = Date()
    var backend: TunnelBackend?
    var backendPath: String
    var routes: [RouteEntry] = []
    var warnings: [String]

    init(name: String, kind: TunnelKind, wireGuard: TunnelConfig?, openVPN: OpenVPNConfig?, backendPath: String) {
        self.name = name
        self.kind = kind
        self.wireGuard = wireGuard
        self.openVPN = openVPN
        self.backendPath = backendPath
        self.warnings = wireGuard?.warnings ?? []
    }

    var routesAllTraffic: Bool {
        if let wireGuard { return wireGuard.isFullTunnel }
        if let backend = backend as? OpenVPNBackend { return backend.fullTunnel || (openVPN?.redirectsGateway ?? false) }
        return openVPN?.redirectsGateway ?? false
    }
}

/// Owns all tunnels. Every method must run on `queue`.
final class TunnelManager {
    let queue = DispatchQueue(label: "com.rtmo0.bridge.helper.manager")
    private var tunnels: [String: ActiveTunnel] = [:]
    private let dns = DNSManager.shared
    private let statePath = "\(AmneziaBackend.runDirectory)/state.json"

    var capabilities: [TunnelKind] {
        OpenVPNBackend.isAvailable ? [.amneziawg, .wireguard, .openvpn] : [.amneziawg, .wireguard]
    }

    // MARK: Requests

    func handle(_ request: HelperRequest) -> HelperResponse {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            switch request.command {
            case .ping:
                return HelperResponse(ok: true, capabilities: capabilities)
            case .status:
                return HelperResponse(ok: true, tunnels: statuses(filter: request.name))
            case .up:
                guard let name = request.name, TunnelName.isValid(name) else {
                    return .failure("Invalid tunnel name", code: .invalidConfig)
                }
                guard let text = request.config else { return .failure("No configuration supplied", code: .invalidConfig) }
                let status = try up(name: name, configText: text, secrets: request.secrets ?? TunnelSecrets(),
                                    settings: request.settings ?? TunnelSettings())
                return HelperResponse(ok: true, tunnels: [status])
            case .down:
                guard let name = request.name else { return .failure("No tunnel name") }
                try down(name: name)
                return HelperResponse(ok: true)
            case .downAll:
                downAll()
                return HelperResponse(ok: true)
            case .openvpnEvent:
                return .failure("openvpnEvent is handled outside the manager queue")
            }
        } catch let error as CodedError {
            return .failure(error.message, code: error.code, detail: error.detail)
        } catch let error as ConfigError {
            return .failure("Invalid configuration: \(error)", code: .invalidConfig)
        } catch {
            return .failure("\(error)")
        }
    }

    // MARK: Up

    private func up(name: String, configText: String, secrets: TunnelSecrets,
                    settings: TunnelSettings) throws -> TunnelStatus {
        guard tunnels[name] == nil else {
            throw CodedError(code: .alreadyConnected, message: "Tunnel '\(name)' is already connected", detail: nil)
        }
        let kind = TunnelKind.detect(configText)
        switch kind {
        case .amneziawg, .wireguard:
            let (config, bypass) = try TunnelConfig.parse(configText).applying(settings)
            return try upWireGuard(name: name, config: config, bypass: bypass)
        case .openvpn:
            guard OpenVPNBackend.isAvailable else {
                throw CodedError(code: .unsupported, message: "OpenVPN is not installed with this Bridge build", detail: nil)
            }
            return try upOpenVPN(name: name, config: try OpenVPNConfig.parse(configText).applying(settings),
                                 secrets: secrets)
        }
    }

    private func checkFullTunnelConflict(_ wantsAll: Bool) throws {
        guard wantsAll, let other = tunnels.values.first(where: { $0.routesAllTraffic }) else { return }
        throw HelperError("'\(other.name)' already routes all traffic. Disconnect it first.")
    }

    private func upWireGuard(name: String, config: TunnelConfig, bypass: [IPNetwork]) throws -> TunnelStatus {
        try checkFullTunnelConflict(config.isFullTunnel)
        let kind: TunnelKind = config.usesAmneziaObfuscation ? .amneziawg : .wireguard
        log("up '\(name)' (\(kind.displayName))")
        let tunnel = ActiveTunnel(name: name, kind: kind, wireGuard: config, openVPN: nil,
                                  backendPath: AmneziaBackend.executablePath)
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
                    let pin = RouteEntry(destination: "\(ip)", ipv6: ip.isIPv6, gateway: current.gateway,
                                         interface: current.gateway == nil ? current.interface : nil)
                    if try Routes.add(pin) { tunnel.routes.append(pin) }
                }
            }

            // Networks excluded from the tunnel keep using the current uplink.
            for network in bypass {
                guard let uplink = Routes.lookup("default", ipv6: network.isIPv6) else { continue }
                let net = network.masked
                let entry = RouteEntry(destination: net.prefix == net.maxPrefix ? "\(net.address)" : net.description,
                                       ipv6: net.isIPv6, gateway: uplink.gateway,
                                       interface: uplink.gateway == nil ? uplink.interface : nil)
                if (try? Routes.add(entry)) == true { tunnel.routes.append(entry) }
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

            if let warning = dns.apply(tunnel: name, DNSSettings(config: config, interface: backend.interface)) {
                tunnel.warnings.append(warning)
            }
            log("up '\(name)' done on \(backend.interface)")
            return status(of: tunnel)
        } catch {
            log("up '\(name)' failed: \(error)")
            teardown(tunnel)
            tunnels[name] = nil
            saveState()
            throw error
        }
    }

    private func upOpenVPN(name: String, config: OpenVPNConfig, secrets: TunnelSecrets) throws -> TunnelStatus {
        try checkFullTunnelConflict(config.redirectsGateway)
        log("up '\(name)' (OpenVPN, \(config.remotes.first ?? "?"))")
        let tunnel = ActiveTunnel(name: name, kind: .openvpn, wireGuard: nil, openVPN: config,
                                  backendPath: OpenVPNBackend.executablePath)
        tunnels[name] = tunnel
        do {
            let (backend, warnings) = try OpenVPNBackend.start(tunnel: name, config: config, secrets: secrets) {
                [weak self] pid in
                self?.queue.async { self?.backendExited(name: name, pid: pid) }
            }
            tunnel.backend = backend
            tunnel.warnings += warnings
            saveState()
            log("up '\(name)' done on \(backend.interface)")
            return status(of: tunnel)
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
        guard let tunnel = tunnels[name] else {
            throw CodedError(code: .notConnected, message: "Tunnel '\(name)' is not connected", detail: nil)
        }
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
        // Stop OpenVPN first: it removes its own routes and calls the down hook.
        tunnel.backend?.stop()
        dns.remove(tunnel: tunnel.name)
        for route in tunnel.routes.reversed() { Routes.delete(route) }
        tunnel.routes.removeAll()
        unlink("\(AmneziaBackend.runDirectory)/\(tunnel.name).ifname")
    }

    private func backendExited(name: String, pid: Int32) {
        guard let tunnel = tunnels[name], let backend = tunnel.backend, backend.pid == pid else { return }
        log("backend of '\(name)' (pid \(pid)) exited, cleaning up")
        teardown(tunnel)
        tunnels[name] = nil
        saveState()
    }

    // MARK: Status

    private func statuses(filter: String?) -> [TunnelStatus] {
        tunnels.values
            .filter { filter == nil || $0.name == filter }
            .sorted { $0.name < $1.name }
            .map(status(of:))
    }

    private func status(of tunnel: ActiveTunnel) -> TunnelStatus {
        if let backend = tunnel.backend as? AmneziaBackend, let config = tunnel.wireGuard {
            let device = (try? backend.status()) ?? UAPI.DeviceStatus()
            let lastHandshake = device.peers.compactMap(\.lastHandshake).max()
            // WireGuard re-handshakes at least every 2 minutes while in use.
            let fresh = lastHandshake.map { Date().timeIntervalSince($0) < 180 } ?? false
            return TunnelStatus(
                name: tunnel.name, kind: tunnel.kind, interface: backend.interface, pid: backend.pid,
                startedAt: tunnel.startedAt, connected: fresh,
                state: lastHandshake == nil ? "Waiting for handshake" : (fresh ? "Connected" : "No recent handshake"),
                server: device.peers.first?.endpoint ?? config.peers.first?.endpoint?.description,
                addresses: config.addresses.map(\.description), dnsServers: config.dnsServers.map(\.description),
                fullTunnel: config.isFullTunnel, lastHandshake: lastHandshake,
                rxBytes: device.peers.reduce(0) { $0 + $1.rxBytes }, txBytes: device.peers.reduce(0) { $0 + $1.txBytes },
                peers: device.peers.map {
                    TunnelStatus.Peer(publicKey: $0.publicKey, endpoint: $0.endpoint,
                                      lastHandshake: $0.lastHandshake, rxBytes: $0.rxBytes, txBytes: $0.txBytes)
                },
                warnings: tunnel.warnings)
        }
        if let backend = tunnel.backend as? OpenVPNBackend {
            let s = backend.snapshot
            let stateNames = ["CONNECTED": "Connected", "RECONNECTING": "Reconnecting", "WAIT": "Waiting for server",
                              "AUTH": "Authenticating", "GET_CONFIG": "Getting configuration",
                              "ASSIGN_IP": "Assigning address", "ADD_ROUTES": "Adding routes",
                              "CONNECTING": "Connecting", "EXITING": "Disconnecting", "RESOLVE": "Resolving server",
                              "TCP_CONNECT": "Connecting (TCP)"]
            return TunnelStatus(
                name: tunnel.name, kind: .openvpn, interface: s.interface, pid: backend.pid, startedAt: tunnel.startedAt,
                connected: s.state == "CONNECTED", state: stateNames[s.state] ?? s.state.capitalized,
                server: s.remote ?? tunnel.openVPN?.remotes.first,
                addresses: [s.localIP, s.localIPv6].compactMap { $0 },
                dnsServers: dns.servers(for: tunnel.name), fullTunnel: tunnel.routesAllTraffic,
                lastHandshake: nil, rxBytes: s.rx, txBytes: s.tx, peers: [],
                warnings: tunnel.warnings + [backend.dnsWarning].compactMap { $0 })
        }
        return TunnelStatus(name: tunnel.name, kind: tunnel.kind, interface: "", pid: 0, startedAt: tunnel.startedAt,
                            connected: false, state: "Starting", server: nil, addresses: [], dnsServers: [],
                            fullTunnel: false, lastHandshake: nil, rxBytes: 0, txBytes: 0, peers: [],
                            warnings: tunnel.warnings)
    }

    // MARK: Crash recovery

    private func saveState() {
        let entries = tunnels.values.map {
            PersistedTunnel(name: $0.name, pid: $0.backend?.pid ?? 0, backendPath: $0.backendPath,
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
                terminate(pid: entry.pid, grace: 5)
                log("  stopped stale backend pid \(entry.pid) of '\(entry.name)'")
            }
            for route in entry.routes.reversed() { Routes.delete(route) }
            dns.remove(tunnel: entry.name)
            for suffix in ["ovpn", "mgmt", "ifname"] { unlink("\(AmneziaBackend.runDirectory)/\(entry.name).\(suffix)") }
        }
        try? FileManager.default.removeItem(atPath: statePath)
    }
}

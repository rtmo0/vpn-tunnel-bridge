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
    let proxy: ProxyLink?
    let proxyRouting: ProxyRouting?
    /// Xray tunnels: IPv6 address and routes are added once the server proves it reaches IPv6.
    var ipv6Active = false
    /// Xray tunnels with a routing profile: what is needed to start them again when the
    /// uplink changes (direct traffic is bound to the uplink interface by name).
    var xrayRequest: (text: String, profile: RoutingProfile, assets: String?)?
    var directInterface: String?
    let startedAt = Date()
    var backend: TunnelBackend?
    var backendPath: String
    var routes: [RouteEntry] = []
    var warnings: [String]
    var settings = TunnelSettings()
    /// VPN server addresses (kept reachable by the kill switch).
    var serverIPs: [String] = []

    init(name: String, kind: TunnelKind, wireGuard: TunnelConfig?, openVPN: OpenVPNConfig?,
         proxy: ProxyLink? = nil, proxyRouting: ProxyRouting? = nil, backendPath: String) {
        self.name = name
        self.kind = kind
        self.wireGuard = wireGuard
        self.openVPN = openVPN
        self.proxy = proxy
        self.proxyRouting = proxyRouting
        self.backendPath = backendPath
        self.warnings = wireGuard?.warnings ?? []
    }

    var routesAllTraffic: Bool {
        if let wireGuard { return wireGuard.isFullTunnel }
        if let proxyRouting { return proxyRouting.isFullTunnel }
        if let backend = backend as? OpenVPNBackend { return backend.fullTunnel || (openVPN?.redirectsGateway ?? false) }
        if let backend = backend as? OpenConnectBackend { return backend.fullTunnel }
        return openVPN?.redirectsGateway ?? false
    }
}

/// Owns all tunnels. Every method must run on `queue`.
final class TunnelManager {
    let queue = DispatchQueue(label: "com.rtmo0.bridge.helper.manager")
    private var tunnels: [String: ActiveTunnel] = [:]
    private let dns = DNSManager.shared
    private let statePath = "\(AmneziaBackend.runDirectory)/state.json"
    let firewall = Firewall()
    /// Tunnels that dropped while their kill switch was on: traffic stays blocked
    /// (except to these servers) until the user disconnects or lifts it.
    private var killSwitchHolds: [String: [String]] = [:]
    /// Interface/gateway used for routes outside the tunnels, to detect network changes.
    private var lastUplink: Routes.Lookup?

    var capabilities: [TunnelKind] {
        var kinds: [TunnelKind] = [.amneziawg, .wireguard]
        if OpenVPNBackend.isAvailable { kinds.append(.openvpn) }
        if XrayBackend.isAvailable { kinds += [.vless, .trojan, .hysteria2] }
        if OpenConnectBackend.isAvailable { kinds.append(.openconnect) }
        return kinds
    }

    // MARK: Requests

    func handle(_ request: HelperRequest) -> HelperResponse {
        dispatchPrecondition(condition: .onQueue(queue))
        do {
            switch request.command {
            case .ping:
                return HelperResponse(ok: true, capabilities: capabilities)
            case .status:
                var response = HelperResponse(ok: true, tunnels: statuses(filter: request.name))
                response.killSwitchHolds = killSwitchHolds.keys.sorted()
                return response
            case .releaseKillSwitch:
                if !killSwitchHolds.isEmpty { log("kill switch lifted by the user") }
                killSwitchHolds.removeAll()
                updateFirewall()
                return HelperResponse(ok: true)
            case .up:
                guard let name = request.name, TunnelName.isValid(name) else {
                    return .failure("Invalid tunnel name", code: .invalidConfig)
                }
                guard let text = request.config else { return .failure("No configuration supplied", code: .invalidConfig) }
                let settings = request.settings ?? TunnelSettings()
                let status = try up(name: name, configText: text, secrets: request.secrets ?? TunnelSecrets(),
                                    settings: settings, profile: request.profile, profileAssets: request.profileAssets)
                tunnels[name]?.settings = settings
                killSwitchHolds[name] = nil
                updateFirewall()
                return HelperResponse(ok: true, tunnels: [status])
            case .down:
                guard let name = request.name else { return .failure("No tunnel name") }
                killSwitchHolds[name] = nil
                if tunnels[name] != nil { try down(name: name) }
                updateFirewall()
                return HelperResponse(ok: true)
            case .downAll:
                killSwitchHolds.removeAll()
                downAll()
                updateFirewall()
                return HelperResponse(ok: true)
            case .openvpnEvent, .openconnectEvent:
                return .failure("Hook events are handled outside the manager queue")
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

    private func up(name: String, configText: String, secrets: TunnelSecrets, settings: TunnelSettings,
                    profile: RoutingProfile? = nil, profileAssets: String? = nil) throws -> TunnelStatus {
        guard tunnels[name] == nil else {
            throw CodedError(code: .alreadyConnected, message: "Tunnel '\(name)' is already connected", detail: nil)
        }
        let kind = TunnelKind.detect(configText)
        if profile != nil && !kind.usesXray {
            throw CodedError(code: .invalidConfig,
                             message: "Routing profiles work with VLESS, Trojan and Hysteria 2 tunnels only", detail: nil)
        }
        switch kind {
        case .amneziawg, .wireguard:
            let (config, bypass) = try TunnelConfig.parse(configText).applying(settings)
            return try upWireGuard(name: name, config: config, bypass: bypass)
        case .openvpn:
            guard OpenVPNBackend.isAvailable else {
                throw CodedError(code: .unsupported, message: "OpenVPN is not installed with this Bridge build", detail: nil)
            }
            return try upOpenVPN(name: name, config: try OpenVPNConfig.parse(configText).applying(settings),
                                 secrets: secrets, settings: settings)
        case .openconnect:
            guard OpenConnectBackend.isAvailable else {
                throw CodedError(code: .unsupported, message: "OpenConnect is not installed with this Bridge build",
                                 detail: nil)
            }
            return try upOpenConnect(name: name, config: try OpenConnectConfig.parse(configText), secrets: secrets,
                                     settings: settings)
        case .vless, .trojan, .hysteria2:
            guard XrayBackend.isAvailable else {
                throw CodedError(code: .unsupported,
                                 message: "\(kind.displayName) needs Xray, which is not installed with this Bridge build",
                                 detail: nil)
            }
            let link = try ProxyLink.parse(configText)
            if settings.routingProfile != nil && profile == nil {
                throw CodedError(code: .invalidConfig, message: "The routing profile was not sent", detail: nil)
            }
            if let profile, settings.killSwitch, profile.sendsTrafficDirect {
                throw CodedError(code: .invalidConfig, message: "The kill switch would block the traffic that routing "
                    + "profile “\(profile.name)” sends direct. Turn one of them off.", detail: nil)
            }
            let status = try upXray(name: name, link: link, routing: try link.routing(settings), profile: profile,
                                    profileAssets: profileAssets)
            if let profile { tunnels[name]?.xrayRequest = (configText, profile, profileAssets) }
            return status
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

            tunnel.serverIPs = resolved.values.map { "\($0.address)" }

            // Pin the route to each server *before* the tunnel routes capture it.
            let allAllowed = config.peers.flatMap(\.allowedIPs)
            var uplinkInterface: String?
            let ours = ourInterfaces
            for (_, endpoint) in resolved {
                let ip = endpoint.address
                guard var path = Routes.lookup("\(ip)", ipv6: ip.isIPv6) else {
                    throw HelperError("No route to server \(ip). Is the network up?")
                }
                // The server must be reached directly, never inside another Bridge tunnel.
                let throughTunnel = path.interface.map(Routes.isVirtual) ?? false
                if throughTunnel, !ip.isIPv6, let uplink = Routes.uplink(excluding: ours) { path = uplink }
                uplinkInterface = uplinkInterface ?? path.interface
                if throughTunnel || allAllowed.contains(where: { $0.contains(ip) }) {
                    let pin = RouteEntry(destination: "\(ip)", ipv6: ip.isIPv6, gateway: path.gateway,
                                         interface: path.gateway == nil ? path.interface : nil)
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
            lastUplink = Routes.uplink(excluding: ourInterfaces)
            ensureServerPins()
            return status(of: tunnel)
        } catch {
            log("up '\(name)' failed: \(error)")
            teardown(tunnel)
            tunnels[name] = nil
            saveState()
            throw error
        }
    }

    private func upOpenVPN(name: String, config: OpenVPNConfig, secrets: TunnelSecrets,
                           settings: TunnelSettings) throws -> TunnelStatus {
        try checkFullTunnelConflict(config.redirectsGateway)
        log("up '\(name)' (OpenVPN, \(config.remotes.first ?? "?"))")
        let tunnel = ActiveTunnel(name: name, kind: .openvpn, wireGuard: nil, openVPN: config,
                                  backendPath: OpenVPNBackend.executablePath)
        tunnels[name] = tunnel
        do {
            // Resolve every server address so they can be reached directly, not inside
            // another tunnel (OpenVPN may connect to any of them).
            var serverIPs: [String] = []
            for remote in config.remotes {
                let host = remote.split(separator: ":").first.map(String.init) ?? remote
                for ip in Resolver.resolveAll(host) where !serverIPs.contains("\(ip)") { serverIPs.append("\(ip)") }
            }
            tunnel.serverIPs = serverIPs
            ensureServerPins()

            let (backend, warnings) = try OpenVPNBackend.start(tunnel: name, config: config, secrets: secrets,
                                                               settings: settings) {
                [weak self] pid in
                self?.queue.async { self?.backendExited(name: name, pid: pid) }
            }
            tunnel.backend = backend
            tunnel.warnings += warnings
            ensureServerPins()
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

    private func upXray(name: String, link: ProxyLink, routing: ProxyRouting, profile: RoutingProfile? = nil,
                        profileAssets: String? = nil) throws -> TunnelStatus {
        try checkFullTunnelConflict(routing.isFullTunnel)
        let transport = link.summary.first { $0.name == "Transport" }?.value ?? ""
        log("up '\(name)' (\(link.kind.displayName) \(transport), \(link.endpoint))")
        let tunnel = ActiveTunnel(name: name, kind: link.kind, wireGuard: nil, openVPN: nil, proxy: link,
                                  proxyRouting: routing, backendPath: XrayBackend.executablePath)
        tunnel.warnings = []
        tunnels[name] = tunnel
        do {
            // Xray gets the server as an IP: resolving it later would go through the tunnel itself.
            let server = try Resolver.resolve(Endpoint(link.endpoint)!)
            let ip = server.address
            tunnel.serverIPs = ["\(ip)"]

            // Pin the server to the physical uplink before the tunnel routes capture it.
            guard var path = Routes.lookup("\(ip)", ipv6: ip.isIPv6) else {
                throw HelperError("No route to server \(ip). Is the network up?")
            }
            let throughTunnel = path.interface.map(Routes.isVirtual) ?? false
            if throughTunnel, !ip.isIPv6, let uplink = Routes.uplink(excluding: ourInterfaces) { path = uplink }
            if throughTunnel || routing.networks.contains(where: { $0.contains(ip) }) {
                let pin = RouteEntry(destination: "\(ip)", ipv6: ip.isIPv6, gateway: path.gateway,
                                     interface: path.gateway == nil ? path.interface : nil)
                if try Routes.add(pin) { tunnel.routes.append(pin) }
            }
            for network in routing.bypass {
                guard let uplink = Routes.lookup("default", ipv6: network.isIPv6) else { continue }
                let net = network.masked
                let entry = RouteEntry(destination: net.prefix == net.maxPrefix ? "\(net.address)" : net.description,
                                       ipv6: net.isIPv6, gateway: uplink.gateway,
                                       interface: uplink.gateway == nil ? uplink.interface : nil)
                if (try? Routes.add(entry)) == true { tunnel.routes.append(entry) }
            }
            saveState()

            var assets: String?
            var directInterface: String?
            if let profile {
                if let profileAssets, profile.needsGeoIP || profile.needsGeoSite {
                    assets = try XrayBackend.installAssets(from: profileAssets, tunnel: name, profile: profile)
                }
                guard let uplink = Routes.uplink(excluding: ourInterfaces)?.interface, !Routes.isVirtual(uplink) else {
                    throw HelperError("No physical network for the direct traffic of routing profile “\(profile.name)”")
                }
                directInterface = uplink
                tunnel.directInterface = uplink
                tunnel.warnings.append("Routing profile “\(profile.name)”: rules decide what goes direct; "
                    + "DNS is answered by the profile's servers.")
                log("  routing profile '\(profile.name)', direct traffic via \(uplink)")
            }
            let backend = try XrayBackend.start(tunnel: name, link: link, serverAddress: "\(ip)", profile: profile,
                                                profileAssets: assets, directInterface: directInterface) {
                [weak self] pid in
                self?.queue.async { self?.backendExited(name: name, pid: pid) }
            }
            tunnel.backend = backend
            saveState()

            var seen = Set<RouteEntry>()
            for network in routing.ipv4Networks {
                for entry in Routes.tunnelRoutes(for: network, interface: backend.interface) where !seen.contains(entry) {
                    seen.insert(entry)
                    if try Routes.add(entry) { tunnel.routes.append(entry) }
                }
            }
            saveState()

            // With a routing profile, Xray answers DNS itself (via the utun's far side).
            let dnsServers = profile == nil ? routing.dnsServers.map(\.description) : [backend.peerIPv4]
            let dns = DNSSettings(servers: dnsServers, searchDomains: profile == nil ? routing.dnsSearchDomains : [],
                                  fullTunnel: routing.isFullTunnel && (profile != nil || !routing.dnsOnlyForDomains),
                                  interface: backend.interface, ipv4Addresses: [backend.localIPv4], ipv6Addresses: [])
            if let warning = self.dns.apply(tunnel: name, dns) { tunnel.warnings.append(warning) }

            backend.onIPv6Available = { [weak self, weak backend] in
                self?.queue.async {
                    guard let self, let backend, self.tunnels[name]?.backend === backend else { return }
                    self.enableIPv6(self.tunnels[name]!, backend: backend)
                }
            }
            backend.startProbing()
            log("up '\(name)' done on \(backend.interface)")
            lastUplink = Routes.uplink(excluding: ourInterfaces)
            ensureServerPins()
            return status(of: tunnel)
        } catch {
            log("up '\(name)' failed: \(error)")
            teardown(tunnel)
            tunnels[name] = nil
            saveState()
            throw error
        }
    }

    /// The proxy server reaches IPv6: give the utun an address and route IPv6 into it.
    private func enableIPv6(_ tunnel: ActiveTunnel, backend: XrayBackend) {
        guard !tunnel.ipv6Active, let routing = tunnel.proxyRouting, !routing.ipv6Networks.isEmpty else { return }
        do {
            try runChecked("/sbin/ifconfig", [backend.interface, "inet6", backend.localIPv6.description, "alias"])
        } catch {
            tunnel.warnings.append("IPv6 could not be enabled: \(error)")
            return
        }
        var seen = Set<RouteEntry>()
        for network in routing.ipv6Networks {
            for entry in Routes.tunnelRoutes(for: network, interface: backend.interface) where !seen.contains(entry) {
                seen.insert(entry)
                if (try? Routes.add(entry)) == true { tunnel.routes.append(entry) }
            }
        }
        tunnel.ipv6Active = true
        log("  '\(tunnel.name)' server reaches IPv6: IPv6 now goes through \(backend.interface)")
        saveState()
        updateFirewall()
    }

    private func upOpenConnect(name: String, config: OpenConnectConfig, secrets: TunnelSecrets,
                               settings: TunnelSettings) throws -> TunnelStatus {
        // Whether it takes all traffic is only known once the server answers; check what we can.
        if settings.routing == .allTraffic || settings.routing == .config {
            if let other = tunnels.values.first(where: { $0.routesAllTraffic }) {
                if settings.routing == .allTraffic {
                    throw HelperError("'\(other.name)' already routes all traffic. Disconnect it first.")
                }
            }
        }
        log("up '\(name)' (OpenConnect \(config.vpnProtocol.rawValue), \(config.host))")
        let tunnel = ActiveTunnel(name: name, kind: .openconnect, wireGuard: nil, openVPN: nil,
                                  backendPath: OpenConnectBackend.executablePath)
        tunnel.warnings = []
        tunnels[name] = tunnel
        do {
            tunnel.serverIPs = Resolver.resolveAll(config.host).filter { !$0.isIPv6 }.map { "\($0)" }
            ensureServerPins()
            let backend = try OpenConnectBackend.start(tunnel: name, config: config, secrets: secrets,
                                                       settings: settings) { [weak self] pid in
                self?.queue.async { self?.backendExited(name: name, pid: pid) }
            }
            tunnel.backend = backend
            if backend.fullTunnel, let other = tunnels.values.first(where: { $0 !== tunnel && $0.routesAllTraffic }) {
                throw HelperError("'\(other.name)' already routes all traffic, and the server of '\(name)' "
                    + "sends all traffic through the VPN. Disconnect '\(other.name)' first.")
            }
            ensureServerPins()
            saveState()
            log("up '\(name)' done on \(backend.interface)")
            lastUplink = Routes.uplink(excluding: ourInterfaces)
            return status(of: tunnel)
        } catch {
            log("up '\(name)' failed: \(error)")
            teardown(tunnel)
            tunnels[name] = nil
            saveState()
            throw error
        }
    }

    /// An OpenConnect tunnel (re)configured itself: follow with the firewall and saved state.
    func openConnectChanged() {
        saveState()
        updateFirewall()
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
        unlink("\(AmneziaBackend.runDirectory)/\(tunnel.name).xray.json")
        try? FileManager.default.removeItem(atPath: "\(AmneziaBackend.runDirectory)/\(tunnel.name).assets")
    }

    private func backendExited(name: String, pid: Int32) {
        guard let tunnel = tunnels[name], let backend = tunnel.backend, backend.pid == pid else { return }
        log("backend of '\(name)' (pid \(pid)) exited, cleaning up")
        let servers = servers(of: tunnel)
        teardown(tunnel)
        tunnels[name] = nil
        if tunnel.settings.killSwitch {
            killSwitchHolds[name] = servers
            log("  kill switch of '\(name)' keeps blocking traffic until it is reconnected or lifted")
        }
        saveState()
        updateFirewall()
    }

    // MARK: Firewall

    private func servers(of tunnel: ActiveTunnel) -> [String] {
        var servers = tunnel.serverIPs
        if let backend = tunnel.backend as? OpenConnectBackend, let gateway = backend.gateway, !servers.contains(gateway) {
            servers.append(gateway)
        }
        if let backend = tunnel.backend as? OpenVPNBackend, let remote = backend.snapshot.remote,
           let host = remote.split(separator: ":").first, IPAddress(String(host)) != nil {
            servers.append(String(host))
        }
        return servers
    }

    /// Recomputes kill switch and IPv6 leak protection from the current tunnels.
    func updateFirewall() {
        var rules = Firewall.Rules()
        for tunnel in tunnels.values.sorted(by: { $0.name < $1.name }) {
            if let interface = tunnel.backend?.interface, !interface.isEmpty {
                rules.tunnelInterfaces.append(interface)
            }
            rules.servers += servers(of: tunnel)
            if tunnel.settings.killSwitch { rules.killSwitch = true }
            // A full tunnel without IPv6 would let IPv6 traffic go around it.
            if tunnel.routesAllTraffic {
                let hasIPv6: Bool
                if let config = tunnel.wireGuard {
                    hasIPv6 = config.addresses.contains(where: \.isIPv6)
                } else if let backend = tunnel.backend as? OpenConnectBackend {
                    hasIPv6 = backend.hasIPv6
                } else if tunnel.proxy != nil {
                    hasIPv6 = tunnel.ipv6Active
                } else if let backend = tunnel.backend as? OpenVPNBackend {
                    hasIPv6 = backend.snapshot.localIPv6 != nil
                } else {
                    hasIPv6 = false
                }
                if !hasIPv6 { rules.blockIPv6 = true }
            }
        }
        for servers in killSwitchHolds.values {
            rules.killSwitch = true
            rules.servers += servers
        }
        rules.servers = Array(Set(rules.servers)).sorted()
        firewall.apply(rules)
    }

    // MARK: Network changes

    /// Called when the primary network changes. Routes that point outside the
    /// tunnels (pinned servers, excluded networks) follow the new uplink, and
    /// OpenVPN tunnels reconnect.
    func networkChanged() {
        let ours = Set(tunnels.values.compactMap { $0.backend?.interface }.filter { !$0.isEmpty })
        guard let uplink = Routes.uplink(excluding: ours) else {
            log("network change: no uplink (offline?)")
            return
        }
        if let last = lastUplink, last.gateway == uplink.gateway, last.interface == uplink.interface { return }
        log("network change: uplink is now \(uplink.gateway ?? "-") on \(uplink.interface ?? "?")")
        lastUplink = uplink

        // Routing-profile tunnels bind direct traffic to the old interface: start them again.
        for tunnel in tunnels.values.sorted(by: { $0.name < $1.name }) {
            guard let request = tunnel.xrayRequest, request.profile.sendsTrafficDirect,
                  tunnel.directInterface != uplink.interface else { continue }
            let name = tunnel.name, settings = tunnel.settings
            log("  restarting '\(name)': its routing profile sends direct traffic via \(uplink.interface ?? "?") now")
            teardown(tunnel)
            tunnels[name] = nil
            do {
                _ = try up(name: name, configText: request.text, secrets: TunnelSecrets(), settings: settings,
                           profile: request.profile, profileAssets: request.assets)
                tunnels[name]?.settings = settings
            } catch {
                log("  could not restart '\(name)': \(error)")
            }
        }

        for tunnel in tunnels.values {
            guard let backend = tunnel.backend else { continue }
            if let vpn = backend as? OpenVPNBackend {
                vpn.reconnect()
                continue
            }
            if let vpn = backend as? OpenConnectBackend {
                vpn.reconnect()
                continue
            }
            var moved: [RouteEntry] = []
            for route in tunnel.routes {
                guard route.interface != backend.interface else {
                    moved.append(route)
                    continue
                }
                let next = RouteEntry(destination: route.destination, ipv6: route.ipv6,
                                      gateway: route.ipv6 ? route.gateway : uplink.gateway,
                                      interface: uplink.gateway == nil ? uplink.interface : nil)
                guard !route.ipv6, next != route else {
                    moved.append(route)
                    continue
                }
                Routes.delete(route)
                if (try? Routes.add(next)) == true { moved.append(next) } else { moved.append(route) }
            }
            tunnel.routes = moved
            log("  '\(tunnel.name)' now reaches its server via \(uplink.interface ?? "?")")
        }
        ensureServerPins()
        saveState()
        updateFirewall()
    }

    // MARK: Server routes

    private var ourInterfaces: Set<String> {
        Set(tunnels.values.compactMap { $0.backend?.interface }.filter { !$0.isEmpty })
    }

    /// Keeps every tunnel's VPN servers on the physical uplink: a server reached
    /// through another tunnel (Bridge's or another VPN app's) means double
    /// encryption and a detour.
    func ensureServerPins() {
        let ours = ourInterfaces
        guard let uplink = Routes.uplink(excluding: ours) else { return }
        for tunnel in tunnels.values {
            for server in servers(of: tunnel) {
                guard let ip = IPAddress(server), !ip.isIPv6,
                      !tunnel.routes.contains(where: { $0.destination == server }),
                      let path = Routes.lookup(server, ipv6: false), let interface = path.interface,
                      Routes.isVirtual(interface), interface != uplink.interface else { continue }
                let pin = RouteEntry(destination: server, ipv6: false, gateway: uplink.gateway,
                                     interface: uplink.gateway == nil ? uplink.interface : nil)
                if (try? Routes.add(pin)) == true {
                    tunnel.routes.append(pin)
                    log("  '\(tunnel.name)' server \(server) now goes directly via \(uplink.interface ?? "?")")
                }
            }
        }
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
        if let backend = tunnel.backend as? OpenConnectBackend {
            let network = backend.network
            let counters = network.flatMap { Interface.counters($0.interface) } ?? (0, 0)
            return TunnelStatus(
                name: tunnel.name, kind: .openconnect, interface: backend.interface, pid: backend.pid,
                startedAt: tunnel.startedAt, connected: backend.state == "Connected", state: backend.state,
                server: backend.config.host,
                addresses: [network?.ipv4, network?.ipv6?.description].compactMap { $0 },
                dnsServers: dns.servers(for: tunnel.name), fullTunnel: backend.fullTunnel, lastHandshake: nil,
                rxBytes: counters.rx, txBytes: counters.tx, peers: [], warnings: tunnel.warnings + backend.warnings)
        }
        if let backend = tunnel.backend as? XrayBackend, let link = tunnel.proxy, let routing = tunnel.proxyRouting {
            let health = backend.health
            let counters = Interface.counters(backend.interface) ?? (0, 0)
            // The probe runs every 30 s while healthy; two misses mean trouble.
            let fresh = health.lastSuccess.map { Date().timeIntervalSince($0) < 75 } ?? false
            let state: String
            if fresh, let latency = health.latency {
                state = "Connected (\(max(1, Int(latency * 1000))) ms)"
            } else if health.lastSuccess == nil && Date().timeIntervalSince(tunnel.startedAt) < 20 {
                state = "Connecting"
            } else {
                state = "Server not responding"
            }
            var addresses = [backend.localIPv4]
            if tunnel.ipv6Active { addresses.append(backend.localIPv6.description) }
            return TunnelStatus(
                name: tunnel.name, kind: link.kind, interface: backend.interface, pid: backend.pid,
                startedAt: tunnel.startedAt, connected: fresh, state: state, server: link.endpoint,
                addresses: addresses, dnsServers: dns.servers(for: tunnel.name), fullTunnel: routing.isFullTunnel,
                lastHandshake: health.lastSuccess, rxBytes: counters.rx, txBytes: counters.tx, peers: [],
                warnings: tunnel.warnings)
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
                            interface: $0.backend?.interface ?? "",
                            routes: $0.routes + (($0.backend as? OpenConnectBackend)?.routes ?? []))
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
        dns.recoverOverride()
        guard let data = FileManager.default.contents(atPath: statePath),
              let entries = try? JSONDecoder.bridge.decode([PersistedTunnel].self, from: data),
              !entries.isEmpty else { return }
        log("cleaning up \(entries.count) tunnel(s) left by a previous run")
        for entry in entries {
            if entry.pid > 0, executablePath(of: entry.pid) == entry.backendPath {
                terminate(pid: entry.pid, grace: 5)
                log("  stopped stale backend pid \(entry.pid) of '\(entry.name)'")
            }
            try? FileManager.default.removeItem(atPath: "\(AmneziaBackend.runDirectory)/\(entry.name).assets")
            for route in entry.routes.reversed() { Routes.delete(route) }
            dns.remove(tunnel: entry.name)
            for suffix in ["ovpn", "mgmt", "ifname", "xray.json"] { unlink("\(AmneziaBackend.runDirectory)/\(entry.name).\(suffix)") }
        }
        try? FileManager.default.removeItem(atPath: statePath)
    }
}

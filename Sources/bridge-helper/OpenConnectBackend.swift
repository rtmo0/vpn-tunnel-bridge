import BridgeCore
import Foundation

/// One running `openconnect`, started with a session cookie from the app's login.
///
/// Bridge is OpenConnect's `vpnc-script` (`bridge-helper openconnect-event`): on
/// `connect` it configures the utun, routes and DNS from what the server
/// assigned, with the tunnel's Bridge settings applied.
final class OpenConnectBackend: TunnelBackend {
    let process: Process
    let tunnel: String
    let config: OpenConnectConfig
    private let settings: TunnelSettings
    private let lock = NSLock()

    // Guarded by `lock`.
    private var _state = "Connecting"
    private var _network: OpenConnectNetwork?
    private var _plan: OpenConnectNetwork.Plan?
    private var _routes: [RouteEntry] = []
    private var _connectedOnce = false
    private var _warnings: [String] = []

    var pid: Int32 { process.processIdentifier }
    var isRunning: Bool { process.isRunning }
    var interface: String { locked { _network?.interface ?? "" } }
    var state: String { locked { _state } }
    var network: OpenConnectNetwork? { locked { _network } }
    var routes: [RouteEntry] { locked { _routes } }
    var warnings: [String] { locked { _warnings } }
    var fullTunnel: Bool { locked { _plan?.isFullTunnel ?? false } }
    var hasIPv6: Bool { locked { _network?.ipv6 != nil && _plan?.networks.contains(where: \.isIPv6) == true } }
    var gateway: String? { locked { _network?.gateway } }

    static var executablePath: String {
        URL(fileURLWithPath: AmneziaBackend.executablePath).deletingLastPathComponent()
            .appendingPathComponent("openconnect").path
    }

    static var isAvailable: Bool { (try? AmneziaBackend.verifyExecutable(executablePath)) != nil }

    private init(process: Process, tunnel: String, config: OpenConnectConfig, settings: TunnelSettings) {
        self.process = process
        self.tunnel = tunnel
        self.config = config
        self.settings = settings
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    /// Starts openconnect with the session and waits until the tunnel is configured.
    static func start(tunnel: String, config: OpenConnectConfig, secrets: TunnelSecrets, settings: TunnelSettings,
                      onExit: @escaping (Int32) -> Void) throws -> OpenConnectBackend {
        guard let cookie = secrets.sessionCookie, let fingerprint = secrets.serverFingerprint else {
            throw CodedError(code: .credentialsRequired, message: "Log in to “\(tunnel)” first", detail: nil)
        }
        let path = executablePath
        try AmneziaBackend.verifyExecutable(path)

        let logPath = "\(AmneziaBackend.logDirectory)/\(tunnel).log"
        if !FileManager.default.fileExists(atPath: logPath) {
            FileManager.default.createFile(atPath: logPath, contents: nil, attributes: [.posixPermissions: 0o644])
        }
        let logHandle = FileHandle(forWritingAtPath: logPath)
        logHandle?.seekToEndOfFile()
        logHandle?.write("\n===== \(Date()) starting OpenConnect for '\(tunnel)' =====\n".data(using: .utf8)!)

        var arguments = ["--protocol", config.vpnProtocol.rawValue, "--cookie-on-stdin", "--non-inter",
                         "--servercert", fingerprint,
                         "--script", "\(AmneziaBackend.helperExecutablePath) openconnect-event",
                         "--reconnect-timeout", "300"]
        if let ua = config.userAgent { arguments += ["--useragent", ua] }
        if let os = config.reportedOS { arguments += ["--os", os] }
        if config.disableDTLS { arguments.append("--no-dtls") }
        if let resolve = secrets.resolve, resolve.contains(":") { arguments += ["--resolve", resolve] }
        // The URL comes from the client. It must be an https:// URL, and "--" ends the options so
        // nothing in it can become one (a second --script would run as root).
        let url = secrets.connectURL ?? config.url
        guard let parsed = URL(string: url), parsed.scheme?.lowercased() == "https", parsed.host?.isEmpty == false else {
            throw HelperError("Invalid server URL for OpenConnect")
        }
        arguments += ["--", url]

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.currentDirectoryURL = URL(fileURLWithPath: AmneziaBackend.runDirectory)
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "BRIDGE_TUNNEL": tunnel]
        let stdin = Pipe()
        process.standardInput = stdin
        process.standardOutput = logHandle ?? FileHandle.nullDevice
        process.standardError = logHandle ?? FileHandle.nullDevice
        process.terminationHandler = { onExit($0.processIdentifier) }

        let backend = OpenConnectBackend(process: process, tunnel: tunnel, config: config, settings: settings)
        OpenConnectRegistry.shared.register(backend)
        do {
            try process.run()
        } catch {
            OpenConnectRegistry.shared.unregister(tunnel)
            throw HelperError("Could not start OpenConnect: \(error)")
        }
        // The cookie never touches the disk or the command line.
        stdin.fileHandleForWriting.write(Data((cookie + "\n").utf8))
        try? stdin.fileHandleForWriting.close()
        log("  openconnect pid \(process.processIdentifier) started (\(config.vpnProtocol.rawValue))")

        let deadline = Date().addingTimeInterval(45)
        while Date() < deadline {
            if backend.locked({ backend._connectedOnce }) { return backend }
            if !process.isRunning { break }
            usleep(100_000)
        }
        backend.stop()
        let tail = (try? String(contentsOfFile: logPath, encoding: .utf8))?
            .split(separator: "\n").suffix(6).joined(separator: "\n") ?? ""
        let expired = tail.contains("401") || tail.lowercased().contains("cookie")
        throw CodedError(code: expired ? .authenticationFailed : nil,
                         message: (process.isRunning ? "OpenConnect did not connect within 45 s"
                                   : "OpenConnect exited") + (tail.isEmpty ? "" : "\nLog:\n\(tail)"),
                         detail: nil)
    }

    func stop() {
        if process.isRunning {
            // SIGTERM makes openconnect log out and run the script with reason=disconnect.
            terminate(pid: process.processIdentifier, grace: 5)
        }
        removeNetwork()
        OpenConnectRegistry.shared.unregister(tunnel)
    }

    /// Network changed: reconnect right away instead of waiting for dead-peer detection.
    func reconnect() {
        if process.isRunning { kill(process.processIdentifier, SIGUSR2) }
    }

    // MARK: vpnc-script events

    func handle(reason: String, environment env: [String: String]) -> HelperResponse {
        switch reason {
        case "pre-init":
            return HelperResponse(ok: true)
        case "connect":
            guard let network = OpenConnectNetwork(environment: env) else {
                return .failure("No interface in the OpenConnect environment")
            }
            do {
                try applyNetwork(network)
            } catch {
                log("  '\(tunnel)' could not configure the tunnel: \(error)")
                return .failure("\(error)")
            }
            locked {
                _state = "Connected"
                _connectedOnce = true
            }
        case "attempt-reconnect":
            locked { _state = "Reconnecting" }
            // The gateway must stay reachable outside the tunnel on the (possibly new) uplink.
            repinGateway()
        case "reconnect":
            locked { _state = "Connected" }
        case "disconnect":
            locked { _state = "Disconnecting" }
            removeNetwork()
        default:
            break
        }
        return HelperResponse(ok: true)
    }

    private func applyNetwork(_ network: OpenConnectNetwork) throws {
        removeNetwork()
        let plan = try network.plan(settings)
        let dev = network.interface
        var added: [RouteEntry] = []
        defer { locked { _routes += added } }

        // 1. Keep the VPN server on the physical uplink before routes into the tunnel exist.
        if let gw = network.gateway, let ip = IPAddress(gw),
           plan.networks.contains(where: { $0.contains(ip) }) || plan.isFullTunnel {
            if let pin = Self.gatewayPin(gw, excluding: dev), (try? Routes.add(pin)) == true { added.append(pin) }
        }

        // 2. Addresses and MTU (utun is point-to-point, like vpnc-script does on macOS).
        var addresses: [IPNetwork] = []
        if let ipv4 = network.ipv4, let net = IPNetwork("\(ipv4)/32") { addresses.append(net) }
        if let ipv6 = network.ipv6 { addresses.append(ipv6) }
        try Interface.configure(dev, addresses: addresses, mtu: network.mtu ?? 1300)
        if let subnet = network.ipv4Network, subnet.prefix < 32 {
            let entry = RouteEntry(destination: subnet.masked.description, ipv6: false, gateway: nil, interface: dev)
            if (try? Routes.add(entry)) == true { added.append(entry) }
        }

        // 3. Routes into the tunnel, then exclusions via the uplink.
        var seen = Set<RouteEntry>()
        for net in plan.networks where !net.isIPv6 || network.ipv6 != nil {
            for entry in Routes.tunnelRoutes(for: net, interface: dev) where !seen.contains(entry) {
                seen.insert(entry)
                if (try? Routes.add(entry)) == true { added.append(entry) }
            }
        }
        for net in plan.bypass {
            guard let uplink = Routes.uplink(excluding: [dev]) else { break }
            guard !net.isIPv6 else { continue }
            let m = net.masked
            let entry = RouteEntry(destination: m.prefix == m.maxPrefix ? "\(m.address)" : m.description, ipv6: false,
                                   gateway: uplink.gateway, interface: uplink.gateway == nil ? uplink.interface : nil)
            if (try? Routes.add(entry)) == true { added.append(entry) }
        }

        // 4. DNS.
        let dns = DNSSettings(servers: plan.dnsServers.map(\.description), searchDomains: plan.searchDomains,
                              fullTunnel: plan.isFullTunnel && !plan.dnsOnlyForDomains, interface: dev,
                              ipv4Addresses: network.ipv4.map { [$0] } ?? [],
                              ipv6Addresses: network.ipv6.map { [("\($0.address)", $0.prefix)] } ?? [])
        let warning = DNSManager.shared.apply(tunnel: tunnel, dns)

        locked {
            _network = network
            _plan = plan
            _warnings = [warning, network.banner.map { "Server message: \($0)" }].compactMap { $0 }
        }
        log("  '\(tunnel)' configured on \(dev): \(network.ipv4 ?? "-"), "
            + (plan.isFullTunnel ? "all traffic" : "\(plan.networks.count) network(s)")
            + (plan.dnsServers.isEmpty ? "" : ", DNS \(plan.dnsServers.map(\.description).joined(separator: " "))"))
        OpenConnectRegistry.shared.onChanged()
    }

    private static func gatewayPin(_ gateway: String, excluding dev: String) -> RouteEntry? {
        guard let ip = IPAddress(gateway), var path = Routes.lookup(gateway, ipv6: ip.isIPv6) else { return nil }
        if path.interface == dev || (path.interface.map(Routes.isVirtual) ?? false && !ip.isIPv6) {
            guard let uplink = Routes.uplink(excluding: [dev]) else { return nil }
            path = uplink
        }
        return RouteEntry(destination: gateway, ipv6: ip.isIPv6, gateway: path.gateway,
                          interface: path.gateway == nil ? path.interface : nil)
    }

    private func repinGateway() {
        guard let network, let gw = network.gateway else { return }
        let old = locked { _routes.filter { $0.destination == gw } }
        for route in old { Routes.delete(route) }
        locked { _routes.removeAll { $0.destination == gw } }
        if let pin = Self.gatewayPin(gw, excluding: network.interface), (try? Routes.add(pin)) == true {
            locked { _routes.append(pin) }
        }
        OpenConnectRegistry.shared.onChanged()
    }

    private func removeNetwork() {
        let routes = locked { () -> [RouteEntry] in
            let r = _routes
            _routes = []
            return r
        }
        for route in routes.reversed() { Routes.delete(route) }
        if !routes.isEmpty || locked({ _network != nil }) { DNSManager.shared.remove(tunnel: tunnel) }
    }
}

/// Finds a tunnel's backend for vpnc-script events without the manager queue,
/// which is busy while `up` waits for the connection.
final class OpenConnectRegistry {
    static let shared = OpenConnectRegistry()
    var onChanged: () -> Void = {}
    private let lock = NSLock()
    private var backends: [String: OpenConnectBackend] = [:]

    func register(_ backend: OpenConnectBackend) {
        lock.withLock { backends[backend.tunnel] = backend }
    }

    func unregister(_ tunnel: String) {
        lock.withLock { backends[tunnel] = nil }
    }

    func handleEvent(tunnel: String?, reason: String, environment env: [String: String]) -> HelperResponse {
        guard let tunnel, let backend = lock.withLock({ backends[tunnel] }) else {
            return .failure("Unknown OpenConnect tunnel")
        }
        // Only the openconnect process of this tunnel may reconfigure it.
        guard env["VPNPID"].flatMap(Int32.init) == backend.pid else {
            log("  ignored OpenConnect event for '\(tunnel)' from another process")
            return .failure("Not this tunnel's process")
        }
        log("openconnect '\(tunnel)' \(reason)")
        return backend.handle(reason: reason, environment: env)
    }
}

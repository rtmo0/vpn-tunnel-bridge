import BridgeCore
import Foundation

/// One running `openvpn` process, driven through its management interface.
///
/// OpenVPN opens the utun and sets its address as root, then switches to the
/// backend account (`user`/`group`, keeping the interface with `persist-tun`).
/// Routes and DNS are the helper's: it adds them from what the route-up hook
/// reports (`route-noexec`) and from the PUSH_REPLY in the management log.
/// Bridge also supplies credentials and tracks state.
final class OpenVPNBackend: TunnelBackend {
    let process: Process
    let tunnel: String
    private let managementPath: String
    private let configPath: String
    private let secrets: TunnelSecrets
    /// DNS overrides from Bridge settings; applied directly, not via OpenVPN's options.
    private let settings: TunnelSettings
    private let lock = NSLock()
    private var managementFD: Int32 = -1

    // State guarded by `lock`.
    private var _state = "STARTING"
    private var _localIP: String?
    private var _localIPv6: String?
    private var _remote: String?
    private var _rx: UInt64 = 0
    private var _tx: UInt64 = 0
    private var _interface = ""
    private var _fullTunnel = false
    private var _failure: (code: HelperErrorCode?, message: String, detail: String?)?
    private var _connectedOnce = false
    /// OpenVPN announced it must reopen the utun (the server pushed different settings on a
    /// reconnect). Running unprivileged it cannot, so it exits: the helper starts it again.
    private var _needsFreshStart = false
    var needsFreshStart: Bool { locked { _needsFreshStart && _connectedOnce } }

    typealias PendingDNS = OpenVPNDNS
    /// The config's own `dns` options; pushed ones are collected from the management log.
    private let localDNSOptions: [[String]]
    /// The config's `pull-filter`s (including Bridge's own from the tunnel settings).
    private let pullFilters: [[String]]
    private var _pushedDNSOptions: [[String]] = []
    /// The last PUSH_REPLY announced more parts (`push-continuation 2`).
    private var _pushContinues = false
    private var _pendingDNS: PendingDNS?
    private var _routesReady = false
    private var _dnsSplitSetting = false
    private var _ipv4: [String] = []
    private var _ipv6: [(String, Int)] = []
    private var _dnsWarning: String?

    var dnsWarning: String? { locked { _dnsWarning } }

    /// Routes the helper added for this tunnel; replaced on every route-up, removed when it stops.
    private var _extraRoutes: [RouteEntry] = []

    /// Adds the routes OpenVPN would have added (it runs with `route-noexec`), from the
    /// route-up environment: redirect-gateway, `route_network_N`, `route_ipv6_network_N`.
    func applyRoutes(environment env: [String: String]) {
        removeRoutes()
        let dev = env["dev"] ?? ""
        guard !dev.isEmpty else { return }
        var added: [RouteEntry] = []
        func add(_ entry: RouteEntry) {
            if (try? Routes.add(entry)) == true { added.append(entry) }
        }
        func outside(_ destination: String) -> RouteEntry? {
            guard let uplink = Routes.uplink(excluding: [dev]) else { return nil }
            return RouteEntry(destination: destination, ipv6: false, gateway: uplink.gateway,
                              interface: uplink.gateway == nil ? uplink.interface : nil)
        }

        // redirect-gateway: keep the server on the physical uplink, then send all IPv4 into the tunnel
        // (as two halves, so the system default route stays untouched).
        if ["1", "2"].contains(env["route_redirect_gateway_ipv4"] ?? "") {
            if let server = env["trusted_ip"], let ip = IPAddress(server), !ip.isIPv6,
               var path = Routes.lookup(server, ipv6: false), path.interface != dev {
                if let interface = path.interface, Routes.isVirtual(interface), let uplink = Routes.uplink(excluding: [dev]) {
                    path = uplink
                }
                add(RouteEntry(destination: server, ipv6: false, gateway: path.gateway,
                               interface: path.gateway == nil ? path.interface : nil))
            }
            for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                add(RouteEntry(destination: half, ipv6: false, gateway: nil, interface: dev))
            }
        }

        // route <network> <netmask> [gateway]: into the tunnel, or outside it for net_gateway.
        let netGateway = env["route_net_gateway"]
        var index = 1
        while let network = env["route_network_\(index)"], let netmask = env["route_netmask_\(index)"] {
            defer { index += 1 }
            guard let prefix = Self.prefixLength(netmask: netmask),
                  let net = IPNetwork("\(network)/\(prefix)")?.masked, !net.isIPv6 else { continue }
            if let gateway = env["route_gateway_\(index)"], gateway == netGateway {
                let destination = net.prefix == 32 ? "\(net.address)" : net.description
                if let entry = outside(destination) { add(entry) }
            } else {
                Routes.tunnelRoutes(for: net, interface: dev).forEach(add)
            }
        }

        // route-ipv6 (redirect-gateway ipv6 arrives as ::/3, 2000::/4, 3000::/4, fc00::/7).
        if env["ifconfig_ipv6_local"] != nil {
            var index6 = 1
            while let network = env["route_ipv6_network_\(index6)"] {
                index6 += 1
                guard let net = IPNetwork(network), net.isIPv6 else { continue }
                Routes.tunnelRoutes(for: net, interface: dev).forEach(add)
            }
        }
        locked { _extraRoutes = added }
    }

    func removeRoutes() {
        let routes = locked { () -> [RouteEntry] in
            let routes = _extraRoutes
            _extraRoutes = []
            return routes
        }
        for route in routes.reversed() { Routes.delete(route) }
    }

    /// The network changed: routes that leave the tunnel (the pinned server,
    /// net_gateway routes) follow the new uplink.
    func moveOutsideRoutes(to uplink: Routes.Lookup) {
        let dev = interface
        let routes = locked { _extraRoutes }
        var moved: [RouteEntry] = []
        for route in routes {
            guard route.interface != dev, !route.ipv6 else {
                moved.append(route)
                continue
            }
            let next = RouteEntry(destination: route.destination, ipv6: false, gateway: uplink.gateway,
                                  interface: uplink.gateway == nil ? uplink.interface : nil)
            guard next != route else {
                moved.append(route)
                continue
            }
            Routes.delete(route)
            moved.append((try? Routes.add(next)) == true ? next : route)
        }
        locked { _extraRoutes = moved }
    }

    static func prefixLength(netmask: String) -> Int? {
        guard let mask = IPAddress(netmask), !mask.isIPv6 else { return nil }
        let bits = mask.bytes.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        let prefix = (~bits).leadingZeroBitCount
        // Contiguous masks only.
        guard prefix == 32 || bits << prefix == 0 else { return nil }
        return prefix
    }

    /// DNS for the current connection: `dns` options (config and pushed) win over dhcp-option.
    func dns(foreignOptions env: [String: String]) -> PendingDNS? {
        let pushed = locked { _pushedDNSOptions }
        return OpenVPNDNS.from(dnsOptions: localDNSOptions + pushed) ?? OpenVPNDNS.from(foreignOptions: env)
    }

    func setDNS(_ dns: PendingDNS?) -> Bool {
        locked {
            _pendingDNS = dns
            return _routesReady
        }
    }

    func setRoutes(interface: String, full: Bool, split: Bool, ipv4: [String], ipv6: [(String, Int)]) -> Bool {
        locked {
            _interface = interface
            _fullTunnel = full
            _dnsSplitSetting = split
            _ipv4 = ipv4
            _ipv6 = ipv6
            _routesReady = true
            return _pendingDNS != nil || settings.dnsMode == .custom
        }
    }

    /// Publishes DNS once both servers and routes are known.
    func applyDNS() {
        let (pushed, interface, full, split, ipv4, ipv6) = locked {
            (_pendingDNS, _interface, _fullTunnel, _dnsSplitSetting, _ipv4, _ipv6)
        }
        guard settings.dnsMode != .system else { return }
        // Bridge settings win over what OpenVPN reports.
        var dns = pushed ?? PendingDNS(servers: [], domains: [], splitDomainsOnly: false)
        if settings.dnsMode == .custom { dns.servers = settings.dnsServers }
        if !settings.splitDNSDomains.isEmpty {
            dns.domains = settings.splitDNSDomains
            dns.splitDomainsOnly = true
        }
        guard !dns.servers.isEmpty else { return }
        // Split DNS (per Bridge settings or OpenVPN resolve-domains): only those domains.
        let primary = full && !split && !dns.splitDomainsOnly
        let settings = DNSSettings(servers: dns.servers, searchDomains: dns.domains, fullTunnel: primary,
                                   interface: interface, ipv4Addresses: ipv4, ipv6Addresses: ipv6)
        let warning = DNSManager.shared.apply(tunnel: tunnel, settings)
        locked { _dnsWarning = warning }
        if let warning { log("  note: \(warning)") }
    }

    var pid: Int32 { process.processIdentifier }
    var isRunning: Bool { process.isRunning }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    var interface: String {
        get { locked { _interface } }
        set { locked { _interface = newValue } }
    }
    var fullTunnel: Bool {
        get { locked { _fullTunnel } }
        set { locked { _fullTunnel = newValue } }
    }
    var state: String { locked { _state } }

    struct Snapshot {
        var state: String
        var localIP: String?
        var localIPv6: String?
        var remote: String?
        var rx: UInt64
        var tx: UInt64
        var interface: String
        var fullTunnel: Bool
    }

    var snapshot: Snapshot {
        locked { Snapshot(state: _state, localIP: _localIP, localIPv6: _localIPv6, remote: _remote, rx: _rx, tx: _tx,
                          interface: _interface, fullTunnel: _fullTunnel) }
    }

    static var executablePath: String {
        URL(fileURLWithPath: AmneziaBackend.executablePath).deletingLastPathComponent()
            .appendingPathComponent("openvpn").path
    }

    static var isAvailable: Bool { (try? AmneziaBackend.verifyExecutable(executablePath)) != nil }

    private init(process: Process, tunnel: String, managementPath: String, configPath: String, secrets: TunnelSecrets,
                 settings: TunnelSettings, localDNSOptions: [[String]], pullFilters: [[String]]) {
        self.settings = settings
        self.localDNSOptions = localDNSOptions
        self.pullFilters = pullFilters
        self.process = process
        self.tunnel = tunnel
        self.managementPath = managementPath
        self.configPath = configPath
        self.secrets = secrets
    }

    /// Starts OpenVPN and waits until it reports CONNECTED (or fails).
    static func start(tunnel: String, config: OpenVPNConfig, secrets: TunnelSecrets, settings: TunnelSettings,
                      onExit: @escaping (Int32) -> Void) throws -> (OpenVPNBackend, [String]) {
        let path = executablePath
        try AmneziaBackend.verifyExecutable(path)

        let run = AmneziaBackend.runDirectory
        let managementPath = "\(run)/\(tunnel).mgmt"
        let configPath = "\(run)/\(tunnel).ovpn"
        unlink(managementPath)

        let helperPath = AmneziaBackend.helperExecutablePath
        // OpenVPN opens the utun as root, then continues as the backend account.
        let account = BackendAccount.current
        let group = getgrgid(account.gid).map { String(cString: $0.pointee.gr_name) } ?? String(account.gid)
        let prepared = try config.prepared(tunnel: tunnel, managementSocket: managementPath,
                                           eventCommand: "\(helperPath) openvpn-event",
                                           runAs: (user: account.name, group: group))
        FileManager.default.createFile(atPath: configPath, contents: Data(prepared.text.utf8),
                                       attributes: [.posixPermissions: 0o600])

        let logPath = "\(AmneziaBackend.logDirectory)/\(tunnel).log"
        if !FileManager.default.fileExists(atPath: logPath) {
            FileManager.default.createFile(atPath: logPath, contents: nil, attributes: [.posixPermissions: 0o644])
        }
        let logHandle = FileHandle(forWritingAtPath: logPath)
        logHandle?.seekToEndOfFile()
        logHandle?.write("\n===== \(Date()) starting OpenVPN for '\(tunnel)' =====\n".data(using: .utf8)!)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["--config", configPath]
        process.currentDirectoryURL = URL(fileURLWithPath: run)
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = logHandle ?? FileHandle.nullDevice
        process.standardError = logHandle ?? FileHandle.nullDevice
        process.terminationHandler = { onExit($0.processIdentifier) }

        let backend = OpenVPNBackend(process: process, tunnel: tunnel, managementPath: managementPath,
                                     configPath: configPath, secrets: secrets, settings: settings,
                                     localDNSOptions: config.dnsOptions, pullFilters: config.pullFilters)
        OpenVPNRegistry.shared.register(backend)
        do {
            try process.run()
        } catch {
            OpenVPNRegistry.shared.unregister(tunnel)
            throw HelperError("Could not start OpenVPN: \(error)")
        }
        log("  openvpn pid \(process.processIdentifier) started")

        do {
            try backend.attachManagement()
            try backend.waitUntilConnected(timeout: 60, logPath: logPath)
        } catch {
            backend.stop()
            throw error
        }
        return (backend, prepared.warnings)
    }

    // MARK: Management interface

    private func attachManagement() throws {
        let deadline = Date().addingTimeInterval(10)
        var fd: Int32 = -1
        while Date() < deadline {
            // Timeout 0: the reader blocks for the lifetime of the connection.
            if let connected = try? UnixSocket.connect(path: managementPath, timeout: 0) {
                fd = connected
                break
            }
            if !process.isRunning { throw HelperError("OpenVPN exited during startup. \(logTail())") }
            usleep(50_000)
        }
        guard fd >= 0 else { throw HelperError("OpenVPN management interface did not appear") }
        locked { managementFD = fd }

        let reader = Thread { [weak self] in self?.readLoop(fd: fd) }
        reader.name = "openvpn-mgmt-\(tunnel)"
        reader.start()

        send("state on")
        // The log carries the PUSH_REPLY, the only place pushed `dns` options show up.
        send("log on")
        send("bytecount 2")
        send("hold release")
    }

    private func send(_ command: String) {
        let fd = locked { managementFD }
        guard fd >= 0 else { return }
        try? UnixSocket.writeAll(fd, command + "\n")
    }

    private static func quoted(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    private func readLoop(fd: Int32) {
        var buffer = [UInt8]()
        var chunk = [UInt8](repeating: 0, count: 8192)
        while true {
            let n = read(fd, &chunk, chunk.count)
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { break }
            buffer.append(contentsOf: chunk[0..<n])
            while let newline = buffer.firstIndex(of: 0x0A) {
                let line = String(decoding: buffer[..<newline], as: UTF8.self)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
                buffer.removeSubrange(...newline)
                handle(line)
            }
        }
    }

    private func fail(_ code: HelperErrorCode?, _ message: String, detail: String? = nil) {
        locked { if _failure == nil { _failure = (code, message, detail) } }
        send("signal SIGTERM")
    }

    private func handle(_ line: String) {
        if line.hasPrefix(">HOLD:") {
            send("hold release")
        } else if line.hasPrefix(">PASSWORD:") {
            handlePassword(String(line.dropFirst(">PASSWORD:".count)))
        } else if line.hasPrefix(">STATE:") {
            let fields = line.dropFirst(">STATE:".count).split(separator: ",", omittingEmptySubsequences: false)
                .map(String.init)
            guard fields.count >= 2 else { return }
            locked {
                _state = fields[1]
                if fields[1] == "CONNECTED" { _connectedOnce = true }
                if fields.count > 3, !fields[3].isEmpty { _localIP = fields[3] }
                if fields.count > 5, !fields[4].isEmpty { _remote = "\(fields[4]):\(fields[5])" }
                if fields.count > 8, !fields[8].isEmpty { _localIPv6 = fields[8] }
            }
            if fields[1] == "CONNECTED" || fields[1] == "RECONNECTING" || fields[1] == "EXITING" {
                log("  '\(tunnel)' \(fields[1])\(fields.count > 2 && !fields[2].isEmpty ? " (\(fields[2]))" : "")")
            }
            if fields[1] == "RECONNECTING", fields.count > 2, fields[2] == "auth-failure" {
                fail(.authenticationFailed, "Authentication failed: wrong username or password")
            }
        } else if line.hasPrefix(">BYTECOUNT:") {
            let parts = line.dropFirst(">BYTECOUNT:".count).split(separator: ",")
            if parts.count == 2 {
                locked {
                    _rx = UInt64(parts[0]) ?? _rx
                    _tx = UInt64(parts[1]) ?? _tx
                }
            }
        } else if line.hasPrefix(">LOG:") {
            // >LOG:{time},{flags},{message}
            let fields = line.dropFirst(">LOG:".count).split(separator: ",", maxSplits: 2, omittingEmptySubsequences: false)
            if fields.count == 3, fields[2].contains("Pulled options changed on restart") {
                locked { _needsFreshStart = true }
                log("  '\(tunnel)' server changed the tunnel settings; OpenVPN will be started again")
            }
            guard fields.count == 3, let options = OpenVPNDNS.pushedOptions(inLogMessage: String(fields[2])) else { return }
            let dnsOptions = OpenVPNDNS.applying(pullFilters: pullFilters, to: options)
                .filter { $0.first == "dns" }.map { Array($0.dropFirst()) }
            let continues = options.contains { $0 == ["push-continuation", "2"] }
            locked {
                // A new PUSH_REPLY replaces the previous connection's options, unless it continues one.
                if !_pushContinues { _pushedDNSOptions = [] }
                _pushedDNSOptions += dnsOptions
                _pushContinues = continues
            }
        } else if line.hasPrefix(">FATAL:") {
            let message = String(line.dropFirst(">FATAL:".count))
            locked { if _failure == nil { _failure = (nil, "OpenVPN: \(message)", nil) } }
        }
    }

    private func handlePassword(_ message: String) {
        if message.hasPrefix("Verification Failed: 'Auth'") {
            fail(.authenticationFailed, "Authentication failed: wrong username or password")
            return
        }
        if message.hasPrefix("Verification Failed: 'Private Key'") {
            fail(.keyPassphraseFailed, "Wrong private key passphrase")
            return
        }
        if message.hasPrefix("Verification Failed") {
            fail(.authenticationFailed, "Authentication failed (\(message))")
            return
        }
        if message.contains("Need 'Auth' username/password") {
            guard let user = secrets.username, let pass = secrets.password else {
                fail(.credentialsRequired, "This server needs a username and password")
                return
            }
            var password = pass
            if let range = message.range(of: "SC:") {
                // Static challenge: "SC:<flags>,<text>". Flag bit 0: echo; bit 1: concatenate.
                let spec = message[range.upperBound...]
                let flags = Int(spec.prefix { $0.isNumber }) ?? 0
                let text = spec.split(separator: ",", maxSplits: 1).dropFirst().first.map(String.init) ?? "Code"
                guard let response = secrets.challengeResponse else {
                    fail(.challengeRequired, "The server asks for a verification code", detail: text)
                    return
                }
                if flags & 2 != 0 {
                    password = pass + response
                } else {
                    password = "SCRV1:\(Data(pass.utf8).base64EncodedString()):\(Data(response.utf8).base64EncodedString())"
                }
            }
            send("username \"Auth\" \(Self.quoted(user))")
            send("password \"Auth\" \(Self.quoted(password))")
        } else if message.contains("Need 'Private Key' password") {
            guard let passphrase = secrets.keyPassphrase else {
                fail(.keyPassphraseRequired, "The private key is protected by a passphrase")
                return
            }
            send("password \"Private Key\" \(Self.quoted(passphrase))")
        } else if message.contains("Need 'HTTP Proxy' username/password") {
            fail(.unsupported, "HTTP proxy authentication is not supported yet")
        } else if message.contains("Need") {
            fail(.unsupported, "OpenVPN asked for something Bridge cannot answer yet: \(message)")
        }
    }

    private func waitUntilConnected(timeout: TimeInterval, logPath: String) throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let (state, failure) = locked { (_state, _failure) }
            if let failure {
                throw CodedError(code: failure.code, message: failure.message, detail: failure.detail)
            }
            if state == "CONNECTED" { return }
            if !process.isRunning {
                throw HelperError("OpenVPN exited before connecting. \(logTail())")
            }
            usleep(100_000)
        }
        throw HelperError("OpenVPN did not connect within \(Int(timeout)) s (last state: \(state)). \(logTail())")
    }

    private func logTail() -> String {
        let path = "\(AmneziaBackend.logDirectory)/\(tunnel).log"
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return "" }
        let lines = text.split(separator: "\n").suffix(6).joined(separator: "\n")
        return lines.isEmpty ? "" : "Last log lines:\n\(lines)"
    }

    /// Soft restart after a network change (OpenVPN re-resolves and reconnects).
    func reconnect() {
        log("  '\(tunnel)' reconnecting after a network change")
        send("signal SIGUSR1")
    }

    func stop() {
        if process.isRunning {
            send("signal SIGTERM")
            let deadline = Date().addingTimeInterval(5)
            while process.isRunning && Date() < deadline { usleep(50_000) }
            if process.isRunning { terminate(pid: process.processIdentifier) }
        }
        let fd = locked { () -> Int32 in
            let fd = managementFD
            managementFD = -1
            return fd
        }
        if fd >= 0 { close(fd) }
        removeRoutes()
        OpenVPNRegistry.shared.unregister(tunnel)
        unlink(configPath)
        unlink(managementPath)
    }
}

/// Errors that carry a code the client can react to (e.g. ask for a password).
struct CodedError: Error, CustomStringConvertible {
    let code: HelperErrorCode?
    let message: String
    let detail: String?
    var description: String { message }
}

/// Lets the route-up/down hook find the backend without going through the
/// manager queue, which is busy while `up` waits for CONNECTED.
final class OpenVPNRegistry {
    static let shared = OpenVPNRegistry()
    /// Called after route-up / down so the firewall can follow the tunnel.
    var onRoutesChanged: () -> Void = {}
    private let lock = NSLock()
    private var backends: [String: OpenVPNBackend] = [:]

    func register(_ backend: OpenVPNBackend) {
        lock.lock()
        backends[backend.tunnel] = backend
        lock.unlock()
    }

    func unregister(_ tunnel: String) {
        lock.lock()
        backends[tunnel] = nil
        lock.unlock()
    }

    func backend(_ tunnel: String) -> OpenVPNBackend? {
        lock.lock()
        defer { lock.unlock() }
        return backends[tunnel]
    }

    /// Handles the hooks OpenVPN runs (`bridge-helper openvpn-event up|down`, tunnel from BRIDGE_TUNNEL):
    /// - `up` (route-up, once the connection is up): add routes and DNS;
    /// - `down` (OpenVPN exits): remove them.
    /// After the first connection OpenVPN runs unprivileged, so its environment is only
    /// believed from processes below that tunnel's OpenVPN (`peerPID` comes from the socket).
    func handleEvent(tunnel name: String?, event: String, environment env: [String: String],
                     peerPID: pid_t?) -> HelperResponse {
        guard let name, let backend = backend(name) else { return .failure("Unknown OpenVPN tunnel") }
        guard let peerPID, PeerAuth.isProcess(peerPID, descendantOf: backend.pid) else {
            log("  ignored OpenVPN event for '\(name)' from another process")
            return .failure("Not this tunnel's process")
        }
        let tunnel = backend.tunnel

        switch event {
        case "up":
            let dev = env["dev"] ?? ""
            guard dev.hasPrefix("utun") else { return .failure("No utun interface in the OpenVPN environment") }
            backend.applyRoutes(environment: env)
            // A full tunnel now sends public destinations to the tunnel device.
            let full = Routes.lookup("1.1.1.1", ipv6: false)?.interface == dev
            var ipv6: [(String, Int)] = []
            if let v6 = env["ifconfig_ipv6_local"] { ipv6.append((v6, Int(env["ifconfig_ipv6_netbits"] ?? "") ?? 64)) }
            let dns = backend.dns(foreignOptions: env)
            log("openvpn '\(tunnel)' route-up on \(dev)\(full ? " (all traffic)" : " (selected networks)")"
                + (dns.map { ", DNS \($0.servers.joined(separator: " "))"
                    + ($0.domains.isEmpty ? "" : " for \($0.domains.joined(separator: ", "))") } ?? ""))
            _ = backend.setDNS(dns)
            let haveDNS = backend.setRoutes(interface: dev, full: full, split: env["BRIDGE_DNS_SPLIT"] == "1",
                                            ipv4: env["ifconfig_local"].map { [$0] } ?? [], ipv6: ipv6)
            if haveDNS { backend.applyDNS() }
            onRoutesChanged()

        case "down":
            log("openvpn '\(tunnel)' down")
            _ = backend.setDNS(nil)
            DNSManager.shared.remove(tunnel: tunnel)
            backend.removeRoutes()
            onRoutesChanged()

        default:
            return .failure("Unknown event '\(event)'")
        }
        return HelperResponse(ok: true)
    }
}

import BridgeCore
import Foundation

/// One running `openvpn` process, driven through its management interface.
///
/// OpenVPN configures the utun interface and routes itself; Bridge supplies
/// credentials, tracks state and applies DNS from the route-up hook.
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

    // DNS arrives from the dns-updown hook, routes from route-up; whichever comes
    // second applies DNS.
    struct PendingDNS {
        var servers: [String]
        var domains: [String]
        var splitDomainsOnly: Bool
    }
    private var _pendingDNS: PendingDNS?
    private var _routesReady = false
    private var _dnsSplitSetting = false
    private var _ipv4: [String] = []
    private var _ipv6: [(String, Int)] = []
    private var _dnsWarning: String?

    var dnsWarning: String? { locked { _dnsWarning } }

    /// Routes Bridge added on OpenVPN's behalf; removed when the tunnel stops.
    private var _extraRoutes: [RouteEntry] = []

    /// OpenVPN cannot redirect the default gateway when the current default route
    /// has no gateway address (e.g. another VPN owns it). Do what it would have done:
    /// pin the server to the current path, then send all IPv4 traffic into the tunnel.
    func redirectAllTraffic(dev: String, server: String?) {
        var added: [RouteEntry] = []
        if let server, let ip = IPAddress(server), let path = Routes.lookup(server, ipv6: ip.isIPv6),
           path.interface != dev {
            let pin = RouteEntry(destination: server, ipv6: ip.isIPv6, gateway: path.gateway,
                                 interface: path.gateway == nil ? path.interface : nil)
            if (try? Routes.add(pin)) == true { added.append(pin) }
        }
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            let entry = RouteEntry(destination: half, ipv6: false, gateway: nil, interface: dev)
            if (try? Routes.add(entry)) == true { added.append(entry) }
        }
        locked { _extraRoutes += added }
        log("  OpenVPN could not redirect the default gateway; Bridge routed all IPv4 traffic through \(dev)")
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
                 settings: TunnelSettings) {
        self.settings = settings
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
        let prepared = try config.prepared(tunnel: tunnel, managementSocket: managementPath,
                                           eventCommand: "\(helperPath) openvpn-event", dnsCommand: helperPath)
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
                                     configPath: configPath, secrets: secrets, settings: settings)
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
        let extra = locked { () -> [RouteEntry] in
            let routes = _extraRoutes
            _extraRoutes = []
            return routes
        }
        for route in extra.reversed() { Routes.delete(route) }
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

    func backend(pid: Int32) -> OpenVPNBackend? {
        lock.lock()
        defer { lock.unlock() }
        return backends.values.first { $0.pid == pid }
    }

    /// Handles hooks run by OpenVPN:
    /// - `up` / `down`: route-up and down (`bridge-helper openvpn-event …`, tunnel from BRIDGE_TUNNEL)
    /// - `dns-up` / `dns-down`: dns-updown (`bridge-helper`, tunnel found by the parent pid)
    func handleEvent(tunnel name: String?, event: String, environment env: [String: String]) -> HelperResponse {
        let found: OpenVPNBackend?
        if let name {
            found = backend(name)
        } else if let ppid = env["BRIDGE_PPID"].flatMap(Int32.init) {
            found = backend(pid: ppid)
        } else {
            found = nil
        }
        guard let backend = found else { return .failure("Unknown OpenVPN tunnel") }
        let tunnel = backend.tunnel

        switch event {
        case "up":
            let dev = env["dev"] ?? ""
            let wantsAll = ["1", "2"].contains(env["route_redirect_gateway_ipv4"] ?? "")
            if wantsAll && env["redirect_gateway"] != "1" {
                backend.redirectAllTraffic(dev: dev, server: env["trusted_ip"])
            }
            // After route-up, a full tunnel sends public destinations to the tunnel device.
            let full = Routes.lookup("1.1.1.1", ipv6: false)?.interface == dev
            var ipv6: [(String, Int)] = []
            if let v6 = env["ifconfig_ipv6_local"] { ipv6.append((v6, Int(env["ifconfig_ipv6_netbits"] ?? "") ?? 64)) }
            log("openvpn '\(tunnel)' route-up on \(dev)\(full ? " (all traffic)" : " (selected networks)")")
            let haveDNS = backend.setRoutes(interface: dev, full: full, split: env["BRIDGE_DNS_SPLIT"] == "1",
                                            ipv4: env["ifconfig_local"].map { [$0] } ?? [], ipv6: ipv6)
            if haveDNS { backend.applyDNS() }
            onRoutesChanged()

        case "dns-up":
            var servers: [String] = []
            var domains: [String] = []
            var splitOnly = false
            for (key, value) in env.sorted(by: { $0.key < $1.key }) {
                if key.hasPrefix("dns_server_"), key.contains("_address_") {
                    // "1.2.3.4", "1.2.3.4 53", "[fd00::1]:53" …
                    var address = String(value.split(separator: " ").first ?? "")
                    if address.hasPrefix("["), let close = address.firstIndex(of: "]") {
                        address = String(address[address.index(after: address.startIndex)..<close])
                    }
                    if IPAddress(address) != nil, !servers.contains(address) { servers.append(address) }
                } else if key.hasPrefix("dns_server_"), key.contains("_resolve_domain_") {
                    splitOnly = true
                    if !domains.contains(value) { domains.append(value) }
                } else if key.hasPrefix("dns_search_domain_") {
                    if !domains.contains(value) { domains.append(value) }
                }
            }
            log("openvpn '\(tunnel)' dns-up: \(servers.isEmpty ? "no servers" : servers.joined(separator: ", "))"
                + (domains.isEmpty ? "" : " for \(domains.joined(separator: ", "))"))
            let routesReady = backend.setDNS(OpenVPNBackend.PendingDNS(servers: servers, domains: domains, splitDomainsOnly: splitOnly))
            if routesReady { backend.applyDNS() }

        case "down", "dns-down":
            log("openvpn '\(tunnel)' \(event)")
            _ = backend.setDNS(nil)
            DNSManager.shared.remove(tunnel: tunnel)

        default:
            return .failure("Unknown event '\(event)'")
        }
        return HelperResponse(ok: true)
    }
}

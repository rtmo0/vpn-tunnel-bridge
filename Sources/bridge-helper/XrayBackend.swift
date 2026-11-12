import BridgeCore
import Foundation

/// One running Xray process for a VLESS, Trojan or Hysteria 2 tunnel.
///
/// Xray creates the utun and turns its packets into proxy connections; Bridge
/// owns routes, DNS and the firewall exactly as for WireGuard. Because Xray's
/// TUN stack accepts every TCP connection locally, a working tunnel is
/// recognised by a real HTTP answer fetched through Xray (the "probe"), not by
/// a handshake.
final class XrayBackend: TunnelBackend {
    let process: Process
    let interface: String
    /// Unit number of the utun, also used to pick non-overlapping addresses.
    let unit: Int
    let configPath: String
    private let probePorts: (ipv4: UInt16, ipv6: UInt16)
    private let lock = NSLock()

    var pid: Int32 { process.processIdentifier }
    var isRunning: Bool { process.isRunning }

    static var executablePath: String {
        URL(fileURLWithPath: AmneziaBackend.executablePath).deletingLastPathComponent()
            .appendingPathComponent("xray").path
    }

    static var isAvailable: Bool { (try? AmneziaBackend.verifyExecutable(executablePath)) != nil }

    /// The utun's local IPv4 address (Xray assigns it: the address after the gateway).
    var localIPv4: String { Self.addresses(unit: unit).local }
    var gateway: String { Self.addresses(unit: unit).gateway }
    /// The utun's far side: the system resolver points here when a routing profile answers DNS.
    var peerIPv4: String { String(gateway.split(separator: "/")[0]) }
    var localIPv6: IPNetwork { IPNetwork("fd62:7269:6467:\(String(unit, radix: 16))::2/64")! }

    /// 198.18.0.0/15 is reserved for benchmarking, so it never clashes with a real network.
    static func addresses(unit: Int) -> (gateway: String, local: String) {
        let base = (unit % 64) * 4
        let third = unit / 64
        return ("198.18.\(third).\(base + 1)/30", "198.18.\(third).\(base + 2)")
    }

    // MARK: Health, guarded by `lock`

    struct Health {
        var lastSuccess: Date?
        var latency: TimeInterval?
        var consecutiveFailures = 0
        /// nil until checked; then whether the server reaches IPv6.
        var ipv6: Bool?
    }
    private var _health = Health()
    private var stopped = false
    var health: Health { lock.withLock { _health } }

    /// Called (on the prober thread) once the server is known to reach IPv6.
    var onIPv6Available: (() -> Void)?

    private init(process: Process, interface: String, unit: Int, configPath: String,
                 probePorts: (ipv4: UInt16, ipv6: UInt16)) {
        self.process = process
        self.interface = interface
        self.unit = unit
        self.configPath = configPath
        self.probePorts = probePorts
    }

    // MARK: Start / stop

    static func start(tunnel: String, link: ProxyLink, serverAddress: String, profile: RoutingProfile? = nil,
                      profileAssets: String? = nil, directInterface: String? = nil,
                      onExit: @escaping (Int32) -> Void) throws -> XrayBackend {
        let path = executablePath
        try AmneziaBackend.verifyExecutable(path)

        guard let unit = (10...250).first(where: { if_nametoindex("utun\($0)") == 0 }) else {
            throw HelperError("No free utun interface")
        }
        let interface = "utun\(unit)"
        let probePorts = (ipv4: try freeLoopbackPort(), ipv6: try freeLoopbackPort())
        let json = try link.xrayConfiguration(address: serverAddress, interface: interface,
                                                gateway: addresses(unit: unit).gateway, mtu: 1500,
                                                probePorts: probePorts, profile: profile,
                                                directInterface: directInterface)
        // The file holds the user ID: root-only, and removed when the tunnel stops.
        let configPath = "\(AmneziaBackend.runDirectory)/\(tunnel).xray.json"
        unlink(configPath)
        guard FileManager.default.createFile(atPath: configPath, contents: json,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw HelperError("Could not write \(configPath)")
        }

        let logPath = "\(AmneziaBackend.logDirectory)/\(tunnel).log"
        if !FileManager.default.fileExists(atPath: logPath) {
            FileManager.default.createFile(atPath: logPath, contents: nil, attributes: [.posixPermissions: 0o644])
        }
        let logHandle = FileHandle(forWritingAtPath: logPath)
        logHandle?.seekToEndOfFile()
        logHandle?.write("\n===== \(Date()) starting Xray for '\(tunnel)' on \(interface) =====\n".data(using: .utf8)!)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["run", "-c", configPath]
        // Keep Xray from looking for geo files or configs anywhere else.
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                               "XRAY_LOCATION_ASSET": profileAssets ?? AmneziaBackend.runDirectory]
        process.currentDirectoryURL = URL(fileURLWithPath: AmneziaBackend.runDirectory)
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = logHandle ?? FileHandle.nullDevice
        process.standardError = logHandle ?? FileHandle.nullDevice
        process.terminationHandler = { onExit($0.processIdentifier) }
        do {
            try process.run()
        } catch {
            unlink(configPath)
            throw HelperError("Could not start Xray: \(error)")
        }
        log("  xray pid \(process.processIdentifier) started")

        let backend = XrayBackend(process: process, interface: interface, unit: unit, configPath: configPath,
                                   probePorts: probePorts)
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if if_nametoindex(interface) != 0, Interface.hasIPv4(interface) { break }
            if !process.isRunning { break }
            usleep(50_000)
        }
        guard process.isRunning, if_nametoindex(interface) != 0 else {
            backend.stop()
            let tail = (try? String(contentsOfFile: logPath, encoding: .utf8))?
                .split(separator: "\n").suffix(5).joined(separator: "\n") ?? ""
            let message = process.isRunning ? "Xray did not create \(interface) within 5 s" : "Xray exited during startup"
            throw HelperError(tail.isEmpty ? message : "\(message)\nXray log:\n\(tail)")
        }
        log("  interface \(interface) ready")
        return backend
    }

    /// Copies a routing profile's geo files into a root-owned folder for Xray.
    /// The source folder belongs to the user; only regular files of sane size are taken.
    static func installAssets(from source: String, tunnel: String, profile: RoutingProfile) throws -> String {
        let destination = "\(AmneziaBackend.runDirectory)/\(tunnel).assets"
        try? FileManager.default.removeItem(atPath: destination)
        try FileManager.default.createDirectory(atPath: destination, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o755])
        for (needed, file) in [(profile.needsGeoIP, "geoip.dat"), (profile.needsGeoSite, "geosite.dat")] where needed {
            let path = "\(source)/\(file)"
            let fd = open(path, O_RDONLY | O_NOFOLLOW)
            guard fd >= 0 else { throw HelperError("Routing profile file \(file) not found") }
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            var info = stat()
            guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size <= 64 << 20 else {
                throw HelperError("Routing profile file \(file) is not a regular file of a sane size")
            }
            let data = handle.readDataToEndOfFile()
            guard FileManager.default.createFile(atPath: "\(destination)/\(file)", contents: data,
                                                 attributes: [.posixPermissions: 0o644]) else {
                throw HelperError("Could not copy \(file)")
            }
        }
        return destination
    }

    func stop() {
        lock.withLock { stopped = true }
        if process.isRunning { terminate(pid: process.processIdentifier) }
        unlink(configPath)
    }

    // MARK: Probing

    /// Checks the tunnel right away and then periodically on a background thread.
    func startProbing() {
        let thread = Thread { [weak self] in self?.probeLoop() }
        thread.name = "xray-probe-\(interface)"
        thread.start()
    }

    private func probeLoop() {
        var ipv6Attempts = 0
        while true {
            if lock.withLock({ stopped }) || !process.isRunning { return }
            let started = Date()
            let ok = Self.probe(port: probePorts.ipv4, timeout: 8)
            let latency = Date().timeIntervalSince(started)
            let firstSuccess: Bool = lock.withLock {
                if ok {
                    let first = _health.lastSuccess == nil
                    _health.lastSuccess = Date()
                    _health.latency = latency
                    _health.consecutiveFailures = 0
                    return first
                }
                _health.consecutiveFailures += 1
                return false
            }
            if firstSuccess { log("  \(interface): tunnel works (\(Int(latency * 1000)) ms)") }

            // IPv6: ask once the tunnel works; retry a couple of times, then give up.
            if ok, health.ipv6 == nil, ipv6Attempts < 3 {
                ipv6Attempts += 1
                if Self.probe(port: probePorts.ipv6, timeout: 6) {
                    lock.withLock { _health.ipv6 = true }
                    onIPv6Available?()
                } else if ipv6Attempts == 3 {
                    lock.withLock { _health.ipv6 = false }
                    log("  '\(interface)' server does not reach IPv6; IPv6 stays blocked")
                }
            }

            // Fast while connecting or failing, relaxed once healthy.
            let healthy = ok && health.ipv6 != nil
            let interval: TimeInterval = healthy ? 30 : (ok ? 2 : min(10, 1 + Double(health.consecutiveFailures)))
            let wake = Date().addingTimeInterval(interval)
            while Date() < wake {
                if lock.withLock({ stopped }) { return }
                usleep(250_000)
            }
        }
    }

    /// Sends a HEAD request through Xray's localhost forwarder. Only a real HTTP
    /// answer from the far side counts.
    static func probe(port: UInt16, timeout: TimeInterval) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { return false }
        let request = "HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nUser-Agent: Bridge\r\nConnection: close\r\n\r\n"
        guard request.withCString({ send(fd, $0, strlen($0), 0) }) > 0 else { return false }
        var buffer = [UInt8](repeating: 0, count: 64)
        var received = 0
        let deadline = Date().addingTimeInterval(timeout)
        while received < 5, Date() < deadline {
            let n = buffer.withUnsafeMutableBytes { recv(fd, $0.baseAddress! + received, 64 - received, 0) }
            if n <= 0 { return false }
            received += n
        }
        return received >= 5 && String(decoding: buffer[0..<5], as: UTF8.self) == "HTTP/"
    }

    /// A localhost TCP port that is free right now (the OS picks it).
    static func freeLoopbackPort() throws -> UInt16 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw HelperError("socket() failed") }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let ok = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, length) == 0 && getsockname(fd, $0, &length) == 0
            }
        }
        guard ok else { throw HelperError("Could not find a free localhost port") }
        return UInt16(bigEndian: addr.sin_port)
    }
}

extension Interface {
    /// True once the interface has an IPv4 address (Xray assigns it shortly after creating the utun).
    static func hasIPv4(_ name: String) -> Bool {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return false }
        defer { freeifaddrs(first) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            if String(cString: entry.pointee.ifa_name) == name, entry.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_INET) {
                return true
            }
            cursor = entry.pointee.ifa_next
        }
        return false
    }

    /// Byte counters of an interface (received, sent).
    ///
    /// Read through netstat: macOS coarsens interface statistics that other
    /// processes get from sysctl/getifaddrs, and netstat is entitled to exact ones.
    static func counters(_ name: String) -> (rx: UInt64, tx: UInt64)? {
        let result = run("/usr/sbin/netstat", ["-ibn", "-I", name])
        guard result.succeeded else { return nil }
        // Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll — utun rows have no
        // Address, so count from the end.
        for line in result.output.split(separator: "\n") where line.contains("<Link#") {
            let cols = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard cols.count >= 8, let rx = UInt64(cols[cols.count - 5]), let tx = UInt64(cols[cols.count - 2]) else {
                continue
            }
            return (rx, tx)
        }
        return nil
    }
}

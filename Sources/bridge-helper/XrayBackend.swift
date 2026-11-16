import BridgeCore
import Foundation

/// One running Xray process for a VLESS, Trojan or Hysteria 2 tunnel.
///
/// The helper creates and addresses the utun and hands it to Xray, which runs
/// unprivileged and turns the packets into proxy connections; Bridge owns
/// routes, DNS and the firewall exactly as for WireGuard. Because Xray's
/// TUN stack accepts every TCP connection locally, a working tunnel is
/// recognised by a real HTTP answer fetched through Xray (the "probe"), not by
/// a handshake.
final class XrayBackend: TunnelBackend {
    let process: SpawnedProcess
    let interface: String
    /// Unit number of the utun, also used to pick non-overlapping addresses.
    let unit: Int
    private let probePorts: (ipv4: UInt16, ipv6: UInt16)
    private let lock = NSLock()

    var pid: Int32 { process.processIdentifier }
    var isRunning: Bool { process.isRunning }

    static var executablePath: String {
        URL(fileURLWithPath: AmneziaBackend.executablePath).deletingLastPathComponent()
            .appendingPathComponent("xray").path
    }

    static var isAvailable: Bool { (try? AmneziaBackend.verifyExecutable(executablePath)) != nil }

    /// The utun's local IPv4 address: the address after the gateway, as Xray itself would assign it.
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

    private init(process: SpawnedProcess, interface: String, unit: Int, probePorts: (ipv4: UInt16, ipv6: UInt16)) {
        self.process = process
        self.interface = interface
        self.unit = unit
        self.probePorts = probePorts
    }

    // MARK: Start / stop

    static func start(tunnel: String, link: ProxyLink, serverAddress: String, profile: RoutingProfile? = nil,
                      profileAssets: String? = nil, directInterface: String? = nil,
                      onExit: @escaping (Int32) -> Void) throws -> XrayBackend {
        let path = executablePath
        try AmneziaBackend.verifyExecutable(path)

        // The unit number picks the addresses, so ask for a specific free one.
        var opened: (fd: Int32, name: String, unit: Int)?
        for candidate in 10...250 where if_nametoindex("utun\(candidate)") == 0 {
            if let utun = try? Utun.open(unit: candidate) {
                opened = (utun.fd, utun.name, candidate)
                break
            }
        }
        guard let (tunFD, interface, unit) = opened else { throw HelperError("No free utun interface") }
        defer { close(tunFD) }  // Xray holds its own copy

        // What Xray does itself when it creates the utun: MTU, then a point-to-point
        // address (local = the address after the gateway).
        let gateway = addresses(unit: unit).gateway
        let gatewayAddress = String(gateway.split(separator: "/")[0])
        try runChecked("/sbin/ifconfig", [interface, "inet", addresses(unit: unit).local, gatewayAddress,
                                          "netmask", "255.255.255.252", "mtu", "1500", "up"])

        let probePorts = (ipv4: try freeLoopbackPort(), ipv6: try freeLoopbackPort())
        let json = try link.xrayConfiguration(address: serverAddress, interface: interface, gateway: gateway,
                                                mtu: 1500, probePorts: probePorts, profile: profile,
                                                directInterface: directInterface)

        // The configuration holds the user ID: it goes through a pipe, never to disk.
        var pipeFDs: [Int32] = [-1, -1]
        guard pipe(&pipeFDs) == 0 else { throw HelperError("pipe() failed: \(String(cString: strerror(errno)))") }
        for fd in pipeFDs { _ = fcntl(fd, F_SETFD, FD_CLOEXEC) }
        let configReader = pipeFDs[0], configWriter = pipeFDs[1]
        defer { close(configReader) }

        let logHandle = AmneziaBackend.openLog(tunnel: tunnel, banner: "starting Xray for '\(tunnel)' on \(interface)")
        defer { if logHandle !== FileHandle.nullDevice { try? logHandle.close() } }
        let account = BackendAccount.current
        let process: SpawnedProcess
        do {
            process = try SpawnedProcess.spawn(
                executable: path, arguments: ["run", "-format", "json", "-c", "stdin:"],
                // The utun arrives as descriptor 3; geo files only from the folder Bridge prepared.
                environment: ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "XRAY_TUN_FD": "3",
                              "XRAY_LOCATION_ASSET": profileAssets ?? AmneziaBackend.runDirectory],
                account: account, workingDirectory: AmneziaBackend.runDirectory,
                stdin: configReader, stdout: logHandle.fileDescriptor, stderr: logHandle.fileDescriptor,
                inherited: [tunFD], onExit: onExit)
        } catch {
            close(configWriter)
            throw error
        }
        // Written after the start: a large configuration would not fit in the pipe buffer.
        DispatchQueue.global().async {
            json.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let written = write(configWriter, raw.baseAddress! + offset, raw.count - offset)
                    if written < 0 && errno == EINTR { continue }
                    if written <= 0 { break }
                    offset += written
                }
            }
            close(configWriter)
        }
        log("  xray pid \(process.processIdentifier) started on \(interface) as \(account.name)")

        let backend = XrayBackend(process: process, interface: interface, unit: unit, probePorts: probePorts)
        // Xray reads its configuration and starts the inbounds; give it a moment to fail on a bad one.
        let deadline = Date().addingTimeInterval(0.5)
        while Date() < deadline, process.isRunning { usleep(50_000) }
        guard process.isRunning else {
            backend.stop()
            let tail = AmneziaBackend.logTail(tunnel: tunnel)
            throw HelperError(tail.isEmpty ? "Xray exited during startup" : "Xray exited during startup\nXray log:\n\(tail)")
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

    static func probe(port: UInt16, timeout: TimeInterval) -> Bool { XrayProbe.check(port: port, timeout: timeout) }

    static func freeLoopbackPort() throws -> UInt16 {
        guard let port = XrayProbe.freeLoopbackPort() else { throw HelperError("Could not find a free localhost port") }
        return port
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

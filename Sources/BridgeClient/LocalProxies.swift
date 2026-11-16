import BridgeCore
import Foundation

/// VLESS, Trojan and Hysteria 2 tunnels in local proxy mode (`TunnelSettings.proxyPort`).
///
/// The app runs Xray itself, as the user: no helper and no administrator rights.
/// Xray offers SOCKS5 and HTTP on 127.0.0.1; only apps set to use that proxy go
/// through it. Proxies stop with the app.
public final class LocalProxies {
    public static let shared = LocalProxies()

    private struct Running {
        let process: Process
        let kind: TunnelKind
        let server: String
        let port: Int
        let probePort: UInt16
        let startedAt: Date
        var lastSuccess: Date?
        var latency: TimeInterval?
    }

    private let lock = NSLock()
    private var running: [String: Running] = [:]
    /// Called on a background thread when a proxy stops by itself.
    public var onExit: (String) -> Void = { _ in }

    /// Xray inside the app bundle (or next to the command-line tool).
    public static var xrayPath: String? {
        let candidates = [Bundle.main.resourceURL?.appendingPathComponent("xray").path,
                          Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("xray").path]
        return candidates.compactMap { $0 }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    public static var logDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Bridge")
    }

    public static func logURL(_ name: String) -> URL { logDirectory.appendingPathComponent("\(name).log") }

    public func isRunning(_ name: String) -> Bool { lock.withLock { running[name] != nil } }

    /// Starts the proxy and returns once Xray is listening (it keeps checking the server afterwards).
    public func start(name: String, text: String, settings: TunnelSettings, profile: RoutingProfile? = nil) throws {
        guard let port = settings.proxyPort else { throw ClientError("“\(name)” is not set to local proxy mode") }
        try settings.validate()
        guard !isRunning(name) else { return }
        guard let xray = Self.xrayPath else { throw ClientError("Xray is not included in this Bridge build") }
        let link = try ProxyLink.parse(text)
        guard XrayProbe.isLoopbackPortFree(UInt16(port)) else {
            throw ClientError("Port \(port) is already in use. Choose another proxy port in the tunnel's settings.")
        }
        guard let probePort = XrayProbe.freeLoopbackPort() else { throw ClientError("No free localhost port") }
        let json = try link.xrayLocalProxyConfiguration(port: port, probePort: probePort, profile: profile)

        try FileManager.default.createDirectory(at: Self.logDirectory, withIntermediateDirectories: true)
        let logURL = Self.logURL(name)
        if !FileManager.default.fileExists(atPath: logURL.path) {
            FileManager.default.createFile(atPath: logURL.path, contents: nil)
        }
        let log = try FileHandle(forWritingTo: logURL)
        log.seekToEndOfFile()
        log.write("\n===== \(Date()) starting local proxy '\(name)' on 127.0.0.1:\(port) =====\n".data(using: .utf8)!)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: xray)
        // The configuration holds the user ID: it goes through a pipe, never to disk.
        process.arguments = ["run", "-format", "json", "-c", "stdin:"]
        var environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        if let profileName = settings.routingProfile {
            environment["XRAY_LOCATION_ASSET"] = RoutingProfiles.folder(profileName).path
        }
        process.environment = environment
        let input = Pipe()
        process.standardInput = input
        process.standardOutput = log
        process.standardError = log
        process.terminationHandler = { [weak self] process in
            guard let self else { return }
            let stopped: Bool = self.lock.withLock {
                guard self.running[name]?.process === process else { return false }
                self.running[name] = nil
                return true
            }
            if stopped { self.onExit(name) }
        }
        try process.run()
        try? log.close()
        DispatchQueue.global().async {
            input.fileHandleForWriting.write(json)
            try? input.fileHandleForWriting.close()
        }

        let entry = Running(process: process, kind: link.kind, server: link.endpoint, port: port, probePort: probePort,
                            startedAt: Date())
        lock.withLock { running[name] = entry }

        // Xray listens within moments; a bad configuration makes it exit.
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline, process.isRunning, XrayProbe.isLoopbackPortFree(UInt16(port)) { usleep(50_000) }
        guard process.isRunning else {
            lock.withLock { running[name] = nil }
            let tail = (try? String(contentsOf: logURL, encoding: .utf8))?
                .split(separator: "\n").suffix(5).joined(separator: "\n") ?? ""
            throw ClientError("Xray exited during startup" + (tail.isEmpty ? "" : "\n\(tail)"))
        }
        startProbing(name, process: process)
    }

    public func stop(_ name: String) {
        guard let entry = lock.withLock({ running.removeValue(forKey: name) }) else { return }
        entry.process.terminate()
    }

    public func stopAll() {
        let all = lock.withLock { () -> [Running] in
            let all = Array(running.values)
            running.removeAll()
            return all
        }
        for entry in all { entry.process.terminate() }
        for entry in all { entry.process.waitUntilExit() }
    }

    /// Statuses in the helper's format, so the app shows proxies like tunnels.
    public func statuses() -> [TunnelStatus] {
        lock.withLock {
            running.sorted { $0.key < $1.key }.map { name, entry in
                let fresh = entry.lastSuccess.map { Date().timeIntervalSince($0) < 75 } ?? false
                let address = "127.0.0.1:\(entry.port)"
                let state: String
                if fresh, let latency = entry.latency {
                    state = "Local proxy (\(max(1, Int(latency * 1000))) ms)"
                } else if entry.lastSuccess == nil && Date().timeIntervalSince(entry.startedAt) < 20 {
                    state = "Connecting"
                } else {
                    state = "Server not responding"
                }
                return TunnelStatus(
                    name: name, kind: entry.kind, interface: "", pid: entry.process.processIdentifier,
                    startedAt: entry.startedAt, connected: fresh, state: state, server: entry.server,
                    addresses: [address], dnsServers: [], fullTunnel: false, lastHandshake: entry.lastSuccess,
                    rxBytes: 0, txBytes: 0, peers: [],
                    warnings: ["Local proxy: apps set to SOCKS5 or HTTP proxy \(address) use it; nothing else does."])
            }
        }
    }

    private func startProbing(_ name: String, process: Process) {
        let thread = Thread { [weak self] in
            var failures = 0
            while let self, let entry = self.lock.withLock({ self.running[name] }), entry.process === process {
                let started = Date()
                let ok = XrayProbe.check(port: entry.probePort, timeout: 8)
                let latency = Date().timeIntervalSince(started)
                self.lock.withLock {
                    guard self.running[name]?.process === process else { return }
                    if ok {
                        self.running[name]?.lastSuccess = Date()
                        self.running[name]?.latency = latency
                    }
                }
                failures = ok ? 0 : failures + 1
                let interval: TimeInterval = ok ? 30 : min(10, 1 + Double(failures))
                let wake = Date().addingTimeInterval(interval)
                while Date() < wake, self.lock.withLock({ self.running[name]?.process === process }) {
                    usleep(250_000)
                }
            }
        }
        thread.name = "proxy-probe-\(name)"
        thread.start()
    }
}

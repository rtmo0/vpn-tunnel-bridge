import BridgeCore
import Foundation

/// One running `amneziawg-go` process and its utun interface.
///
/// The same backend also serves plain WireGuard configs: without obfuscation
/// parameters AmneziaWG is wire-compatible with WireGuard.
final class AmneziaBackend {
    static let uapiDirectory = "/var/run/amneziawg"
    static let runDirectory = "/var/run/bridge"
    static let logDirectory = "/var/log/bridge"

    let process: Process
    let interface: String

    var pid: Int32 { process.processIdentifier }
    var isRunning: Bool { process.isRunning }
    var uapiPath: String { "\(Self.uapiDirectory)/\(interface).sock" }

    /// Location of the bundled backend binary, next to the helper executable.
    static var executablePath: String {
        let helper = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
        return helper.resolvingSymlinksInPath().deletingLastPathComponent()
            .appendingPathComponent("amneziawg-go").path
    }

    /// The helper runs as root, so it must never execute a file that a regular user could replace.
    static func verifyExecutable(_ path: String) throws {
        var info = stat()
        guard stat(path, &info) == 0 else { throw HelperError("Backend not found at \(path)") }
        guard info.st_uid == 0 else { throw HelperError("Backend \(path) must be owned by root") }
        guard info.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
            throw HelperError("Backend \(path) must not be writable by group or others")
        }
        guard access(path, X_OK) == 0 else { throw HelperError("Backend \(path) is not executable") }
    }

    private init(process: Process, interface: String) {
        self.process = process
        self.interface = interface
    }

    /// Starts the backend and waits until its utun interface and UAPI socket exist.
    static func start(tunnel: String, onExit: @escaping (Int32) -> Void) throws -> AmneziaBackend {
        let path = executablePath
        try verifyExecutable(path)

        let nameFile = "\(runDirectory)/\(tunnel).ifname"
        unlink(nameFile)

        let logPath = "\(logDirectory)/\(tunnel).log"
        if !FileManager.default.fileExists(atPath: logPath) {
            FileManager.default.createFile(atPath: logPath, contents: nil, attributes: [.posixPermissions: 0o644])
        }
        let logHandle = FileHandle(forWritingAtPath: logPath)
        logHandle?.seekToEndOfFile()
        logHandle?.write("\n===== \(Date()) starting backend for '\(tunnel)' =====\n".data(using: .utf8)!)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["-f", "utun"]
        process.environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "WG_TUN_NAME_FILE": nameFile,
            "LOG_LEVEL": "verbose",
        ]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = logHandle ?? FileHandle.nullDevice
        process.standardError = logHandle ?? FileHandle.nullDevice
        process.terminationHandler = { onExit($0.processIdentifier) }

        do {
            try process.run()
        } catch {
            throw HelperError("Could not start backend: \(error)")
        }
        log("  backend pid \(process.processIdentifier) started")

        func fail(_ message: String) -> HelperError {
            if process.isRunning { terminate(pid: process.processIdentifier) }
            let tail = (try? String(contentsOfFile: logPath, encoding: .utf8))?
                .split(separator: "\n").suffix(5).joined(separator: "\n") ?? ""
            return HelperError(tail.isEmpty ? message : "\(message)\nBackend log:\n\(tail)")
        }

        // 1. The kernel picks the utun number; the backend writes it to the name file.
        var interface: String?
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if let name = try? String(contentsOfFile: nameFile, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines), name.hasPrefix("utun") {
                interface = name
                break
            }
            if !process.isRunning { throw fail("Backend exited during startup") }
            usleep(50_000)
        }
        guard let interface else { throw fail("Backend did not report its utun interface within 5 s") }

        // 2. Wait for the control socket.
        let backend = AmneziaBackend(process: process, interface: interface)
        let socketDeadline = Date().addingTimeInterval(5)
        while Date() < socketDeadline {
            var info = stat()
            if stat(backend.uapiPath, &info) == 0 && (info.st_mode & S_IFMT) == S_IFSOCK { break }
            if !process.isRunning { throw fail("Backend exited before creating its control socket") }
            usleep(50_000)
        }
        guard FileManager.default.fileExists(atPath: backend.uapiPath) else {
            throw fail("Backend did not create \(backend.uapiPath) within 5 s")
        }
        log("  interface \(interface) ready")
        return backend
    }

    /// Sends one UAPI transaction and returns the raw response.
    func uapi(_ request: String) throws -> String {
        let fd = try UnixSocket.connect(path: uapiPath, timeout: 10)
        defer { close(fd) }
        try UnixSocket.writeAll(fd, request)
        return try UnixSocket.read(fd, until: "\n\n")
    }

    func configure(_ config: TunnelConfig, endpoints: [String: String]) throws {
        let request = try UAPI.setRequest(for: config, endpoints: endpoints)
        let response = try uapi(request)
        let code = UAPI.errno(in: response)
        guard code == 0 else {
            throw HelperError("Backend rejected the configuration (errno \(code)). "
                + "See \(Self.logDirectory) for details.")
        }
        let applied = config.deviceParameters.map(\.name)
        log("  configured: " + (applied.isEmpty ? "plain WireGuard" : applied.joined(separator: " ")))
    }

    func status() throws -> UAPI.DeviceStatus {
        try UAPI.parseGetResponse(try uapi(UAPI.getRequest))
    }

    func stop() {
        guard process.isRunning else { return }
        terminate(pid: process.processIdentifier)
    }
}

/// Resolves endpoint host names (IPv4 preferred, like most clients).
enum Resolver {
    struct Resolved {
        let address: IPAddress
        let port: UInt16
        var uapiValue: String { address.isIPv6 ? "[\(address)]:\(port)" : "\(address):\(port)" }
    }

    static func resolve(_ endpoint: Endpoint) throws -> Resolved {
        if let ip = IPAddress(endpoint.host) { return Resolved(address: ip, port: endpoint.port) }

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var result: UnsafeMutablePointer<addrinfo>?
        let code = getaddrinfo(endpoint.host, nil, &hints, &result)
        guard code == 0, let first = result else {
            throw HelperError("Could not resolve \(endpoint.host): \(String(cString: gai_strerror(code)))")
        }
        defer { freeaddrinfo(first) }

        var candidates: [IPAddress] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let info = cursor {
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen, &host, socklen_t(host.count),
                           nil, 0, NI_NUMERICHOST) == 0,
               let ip = IPAddress(String(cString: host).split(separator: "%").first.map(String.init) ?? "") {
                candidates.append(ip)
            }
            cursor = info.pointee.ai_next
        }
        guard let chosen = candidates.first(where: { !$0.isIPv6 }) ?? candidates.first else {
            throw HelperError("\(endpoint.host) has no usable address")
        }
        log("  resolved \(endpoint.host) -> \(chosen)")
        return Resolved(address: chosen, port: endpoint.port)
    }
}

/// Only root and members of the `admin` group may control tunnels.
enum PeerAuth {
    static let adminGroupID: gid_t = 80

    static func isAuthorized(fd: Int32) -> (Bool, uid_t) {
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0 else { return (false, uid) }
        if uid == 0 { return (true, uid) }
        guard let passwd = getpwuid(uid) else { return (false, uid) }
        var count: Int32 = 64
        var groups = [Int32](repeating: 0, count: Int(count))
        if getgrouplist(passwd.pointee.pw_name, Int32(bitPattern: passwd.pointee.pw_gid), &groups, &count) < 0 {
            groups = [Int32](repeating: 0, count: 1024)
            count = 1024
            _ = getgrouplist(passwd.pointee.pw_name, Int32(bitPattern: passwd.pointee.pw_gid), &groups, &count)
        }
        let isAdmin = groups.prefix(Int(count)).contains(Int32(adminGroupID))
        return (isAdmin, uid)
    }
}

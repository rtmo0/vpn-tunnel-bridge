import BridgeCore
import Foundation

/// One running `amneziawg-go` process and its utun interface.
///
/// The same backend also serves plain WireGuard configs: without obfuscation
/// parameters AmneziaWG is wire-compatible with WireGuard.
final class AmneziaBackend: TunnelBackend {
    static let uapiDirectory = "/var/run/amneziawg"
    static let runDirectory = "/var/run/bridge"
    static let logDirectory = "/var/log/bridge"

    let process: SpawnedProcess
    let interface: String

    var pid: Int32 { process.processIdentifier }
    var isRunning: Bool { process.isRunning }
    var uapiPath: String { Self.uapiPath(interface) }
    static func uapiPath(_ interface: String) -> String { "\(uapiDirectory)/\(interface).sock" }

    static var helperExecutablePath: String {
        (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])).resolvingSymlinksInPath().path
    }

    /// Location of the bundled backend binary, next to the helper executable.
    static var executablePath: String {
        URL(fileURLWithPath: helperExecutablePath).deletingLastPathComponent()
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

    private init(process: SpawnedProcess, interface: String) {
        self.process = process
        self.interface = interface
    }

    /// Opens (creating if needed) a tunnel's log file for a backend's stdout/stderr.
    static func openLog(tunnel: String, banner: String) -> FileHandle {
        let logPath = "\(logDirectory)/\(tunnel).log"
        if !FileManager.default.fileExists(atPath: logPath) {
            FileManager.default.createFile(atPath: logPath, contents: nil, attributes: [.posixPermissions: 0o644])
        }
        guard let handle = FileHandle(forWritingAtPath: logPath) else { return FileHandle.nullDevice }
        handle.seekToEndOfFile()
        handle.write("\n===== \(Date()) \(banner) =====\n".data(using: .utf8)!)
        return handle
    }

    static func logTail(tunnel: String, lines: Int = 5) -> String {
        (try? String(contentsOfFile: "\(logDirectory)/\(tunnel).log", encoding: .utf8))?
            .split(separator: "\n").suffix(lines).joined(separator: "\n") ?? ""
    }

    /// Creates the utun and the UAPI socket as root, then starts the backend
    /// unprivileged with both handed over as descriptors 3 and 4.
    static func start(tunnel: String, onExit: @escaping (Int32) -> Void) throws -> AmneziaBackend {
        let path = executablePath
        try verifyExecutable(path)

        let (tunFD, interface) = try Utun.open()
        defer { close(tunFD) }  // the backend holds its own copy; the utun lives as long as it runs
        // Root-owned and 0600: only the helper can configure the backend.
        let socketPath = uapiPath(interface)
        let uapiFD = try UnixSocket.listen(path: socketPath, mode: 0o600)
        defer { close(uapiFD) }

        let logHandle = openLog(tunnel: tunnel, banner: "starting backend for '\(tunnel)' on \(interface)")
        defer { if logHandle !== FileHandle.nullDevice { try? logHandle.close() } }
        let account = BackendAccount.current
        let process: SpawnedProcess
        do {
            process = try SpawnedProcess.spawn(
                executable: path, arguments: ["-f", interface],
                environment: [
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "WG_TUN_FD": "3",
                    "WG_UAPI_FD": "4",
                    "WG_PROCESS_FOREGROUND": "1",
                    "LOG_LEVEL": "verbose",
                ],
                account: account, workingDirectory: runDirectory,
                stdin: -1, stdout: logHandle.fileDescriptor,
                stderr: logHandle.fileDescriptor, inherited: [tunFD, uapiFD], onExit: onExit)
        } catch {
            unlink(socketPath)
            throw error
        }
        log("  backend pid \(process.processIdentifier) started on \(interface) as \(account.name)")

        // The backend answers on the socket once it is up.
        let backend = AmneziaBackend(process: process, interface: interface)
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if !process.isRunning { break }
            if (try? backend.uapi(UAPI.getRequest, timeout: 1)) != nil {
                log("  interface \(interface) ready")
                return backend
            }
            usleep(50_000)
        }
        backend.stop()
        let message = process.isRunning ? "Backend did not answer on \(socketPath) within 5 s"
            : "Backend exited during startup"
        let tail = logTail(tunnel: tunnel)
        throw HelperError(tail.isEmpty ? message : "\(message)\nBackend log:\n\(tail)")
    }

    /// Sends one UAPI transaction and returns the raw response.
    func uapi(_ request: String, timeout: Int = 10) throws -> String {
        let fd = try UnixSocket.connect(path: uapiPath, timeout: timeout)
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
        if process.isRunning { terminate(pid: process.processIdentifier) }
        // The backend cannot remove the root-owned socket itself.
        unlink(uapiPath)
    }
}

/// Resolves endpoint host names (IPv4 preferred, like most clients).
enum Resolver {
    struct Resolved {
        let address: IPAddress
        let port: UInt16
        var uapiValue: String { address.isIPv6 ? "[\(address)]:\(port)" : "\(address):\(port)" }
    }

    /// Every IPv4/IPv6 address of `host` (OpenVPN may pick any of them).
    static func resolveAll(_ host: String) -> [IPAddress] {
        if let ip = IPAddress(host) { return [ip] }
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else { return [] }
        defer { freeaddrinfo(first) }
        var out: [IPAddress] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let info = cursor {
            var name = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen, &name, socklen_t(name.count),
                           nil, 0, NI_NUMERICHOST) == 0,
               let ip = IPAddress(String(cString: name).split(separator: "%").first.map(String.init) ?? ""),
               !out.contains(ip) {
                out.append(ip)
            }
            cursor = info.pointee.ai_next
        }
        return out
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

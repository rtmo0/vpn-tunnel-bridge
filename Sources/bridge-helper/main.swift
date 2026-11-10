import BridgeCore
import Foundation

// bridge-helper: privileged daemon that brings tunnels up and down.
// Started by launchd as root (see scripts/install.sh).

setvbuf(stdout, nil, _IOLBF, 0)
signal(SIGPIPE, SIG_IGN)

// OpenVPN 2.7 runs `bridge-helper` (no arguments) as its dns-updown command with
// script_type=dns-up|dns-down and the DNS settings in the environment. The tunnel
// is identified by the parent process, which is that tunnel's openvpn.
if let scriptType = ProcessInfo.processInfo.environment["script_type"],
   scriptType == "dns-up" || scriptType == "dns-down" {
    var env = ProcessInfo.processInfo.environment.filter { key, _ in key == "dev" || key.hasPrefix("dns_") }
    env["BRIDGE_PPID"] = String(getppid())
    let request = HelperRequest(command: .openvpnEvent, event: scriptType, environment: env)
    if let fd = try? UnixSocket.connect(path: HelperProtocol.socketPath, timeout: 10),
       let data = try? JSONEncoder.bridge.encode(request) {
        try? UnixSocket.writeAll(fd, String(decoding: data, as: UTF8.self) + "\n")
        _ = try? UnixSocket.read(fd, until: "\n")
        close(fd)
    }
    exit(0)
}

// `bridge-helper openvpn-event up|down` is the route-up/down hook that OpenVPN
// runs (as root). It forwards the event and OpenVPN's environment to the daemon.
if CommandLine.arguments.count >= 3, CommandLine.arguments[1] == "openvpn-event" {
    let env = ProcessInfo.processInfo.environment
    let wanted = env.filter { key, _ in
        key == "dev" || key.hasPrefix("foreign_option_") || key.hasPrefix("dns_") || key.hasPrefix("ifconfig_")
            || key.hasPrefix("BRIDGE_")
    }
    let request = HelperRequest(command: .openvpnEvent, name: env["BRIDGE_TUNNEL"],
                                event: CommandLine.arguments[2], environment: wanted)
    if let fd = try? UnixSocket.connect(path: HelperProtocol.socketPath, timeout: 10),
       let data = try? JSONEncoder.bridge.encode(request) {
        try? UnixSocket.writeAll(fd, String(decoding: data, as: UTF8.self) + "\n")
        _ = try? UnixSocket.read(fd, until: "\n")
        close(fd)
    }
    // Never fail the connection because of DNS.
    exit(0)
}

guard getuid() == 0 else {
    FileHandle.standardError.write("bridge-helper must run as root (it is started by launchd).\n".data(using: .utf8)!)
    exit(1)
}

for directory in [AmneziaBackend.runDirectory, AmneziaBackend.logDirectory] {
    try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                             attributes: [.posixPermissions: 0o755])
}

log("bridge-helper starting (protocol \(HelperProtocol.version), backend \(AmneziaBackend.executablePath))")
do {
    try AmneziaBackend.verifyExecutable(AmneziaBackend.executablePath)
} catch {
    log("! \(error)")
}
log(OpenVPNBackend.isAvailable ? "OpenVPN backend: \(OpenVPNBackend.executablePath)" : "OpenVPN backend not installed")

let manager = TunnelManager()
let installedBuild = (try? String(contentsOfFile: URL(fileURLWithPath: AmneziaBackend.helperExecutablePath)
    .deletingLastPathComponent().appendingPathComponent("version").path, encoding: .utf8))?
    .trimmingCharacters(in: .whitespacesAndNewlines)
manager.queue.sync { manager.recoverFromPreviousRun() }

// Disconnect everything cleanly when launchd stops us.
var signalSources: [DispatchSourceSignal] = []
for sig in [SIGTERM, SIGINT] {
    signal(sig, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: sig, queue: manager.queue)
    source.setEventHandler {
        log("signal \(sig): disconnecting all tunnels")
        manager.downAll()
        unlink(HelperProtocol.socketPath)
        exit(0)
    }
    source.resume()
    signalSources.append(source)
}

let listener: Int32
do {
    // World-connectable; every connection is checked with getpeereid() below.
    listener = try UnixSocket.listen(path: HelperProtocol.socketPath, mode: 0o666)
} catch {
    log("! cannot listen on \(HelperProtocol.socketPath): \(error)")
    exit(1)
}
log("listening on \(HelperProtocol.socketPath)")

func serve(_ fd: Int32) {
    defer { close(fd) }
    UnixSocket.setTimeout(fd, seconds: 60)

    let (authorized, uid) = PeerAuth.isAuthorized(fd: fd)
    func reply(_ response: HelperResponse) {
        guard let data = try? JSONEncoder.bridge.encode(response) else { return }
        try? UnixSocket.writeAll(fd, String(decoding: data, as: UTF8.self) + "\n")
    }
    guard authorized else {
        log("rejected request from uid \(uid) (not an administrator)")
        reply(.failure("Only administrators can control tunnels"))
        return
    }

    guard let line = try? UnixSocket.read(fd, until: "\n", limit: 1 << 20),
          let request = try? JSONDecoder.bridge.decode(HelperRequest.self, from: Data(line.utf8)) else {
        reply(.failure("Malformed request"))
        return
    }
    if request.command == .ping {
        // Answered without the manager queue so clients don't time out while a tunnel connects.
        var response = HelperResponse(ok: true, capabilities: manager.capabilities)
        response.helperBuild = installedBuild
        reply(response)
        return
    }
    if request.command == .openvpnEvent {
        // Comes from OpenVPN while `up` may still hold the manager queue.
        guard uid == 0, let event = request.event else {
            reply(.failure("Not allowed"))
            return
        }
        reply(OpenVPNRegistry.shared.handleEvent(tunnel: request.name, event: event,
                                                 environment: request.environment ?? [:]))
        return
    }
    let response = manager.queue.sync { manager.handle(request) }
    reply(response)
}

let acceptThread = Thread {
    while true {
        let client = accept(listener, nil, nil)
        if client < 0 {
            if errno == EINTR { continue }
            log("! accept failed: \(String(cString: strerror(errno)))")
            sleep(1)
            continue
        }
        DispatchQueue.global().async { serve(client) }
    }
}
acceptThread.start()

dispatchMain()

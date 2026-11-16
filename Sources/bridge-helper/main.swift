import BridgeCore
import Foundation

// bridge-helper: privileged daemon that brings tunnels up and down.
// Started by launchd as root (see scripts/install.sh).

// `bridge-helper drop-exec …`: how the daemon starts a backend unprivileged (see Privileges.swift).
if CommandLine.arguments.count >= 2, CommandLine.arguments[1] == "drop-exec" {
    dropPrivilegesAndExec(Array(CommandLine.arguments.dropFirst(2)))
}

setvbuf(stdout, nil, _IOLBF, 0)
signal(SIGPIPE, SIG_IGN)

// `bridge-helper openvpn-event up|down` is the route-up/down hook that OpenVPN runs
// (as root on the first connection, as the backend account after that). It forwards
// the event and OpenVPN's environment to the daemon, which adds routes and DNS.
if CommandLine.arguments.count >= 3, CommandLine.arguments[1] == "openvpn-event" {
    let env = ProcessInfo.processInfo.environment
    let wanted = env.filter { key, _ in
        key == "dev" || key.hasPrefix("foreign_option_") || key.hasPrefix("ifconfig_")
            || key.hasPrefix("BRIDGE_") || key == "trusted_ip" || key.hasPrefix("route_")
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

// `bridge-helper openconnect-event` is OpenConnect's vpnc-script (run as root on connect,
// as the backend account after openconnect dropped privileges): it
// forwards the reason and the server-assigned settings to the daemon and waits,
// because OpenConnect expects the interface configured when the script returns.
if CommandLine.arguments.count >= 2, CommandLine.arguments[1] == "openconnect-event" {
    let env = ProcessInfo.processInfo.environment
    let wanted = env.filter { key, _ in
        key.hasPrefix("INTERNAL_IP") || key.hasPrefix("CISCO_") || ["reason", "TUNDEV", "VPNGATEWAY", "VPNPID"].contains(key)
    }
    let request = HelperRequest(command: .openconnectEvent, name: env["BRIDGE_TUNNEL"], event: env["reason"],
                                environment: wanted)
    var ok = true
    if let fd = try? UnixSocket.connect(path: HelperProtocol.socketPath, timeout: 30),
       let data = try? JSONEncoder.bridge.encode(request) {
        try? UnixSocket.writeAll(fd, String(decoding: data, as: UTF8.self) + "\n")
        if let line = try? UnixSocket.read(fd, until: "\n"),
           let response = try? JSONDecoder.bridge.decode(HelperResponse.self, from: Data(line.utf8)) {
            ok = response.ok
        }
        close(fd)
    }
    // A failed "connect" makes OpenConnect give up instead of running unconfigured.
    exit(ok || env["reason"] != "connect" ? 0 : 1)
}

guard getuid() == 0 else {
    FileHandle.standardError.write("bridge-helper must run as root (it is started by launchd).\n".data(using: .utf8)!)
    exit(1)
}

for directory in [AmneziaBackend.runDirectory, AmneziaBackend.logDirectory, AmneziaBackend.uapiDirectory] {
    try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                             attributes: [.posixPermissions: 0o755])
}

log("bridge-helper starting (protocol \(HelperProtocol.version), backend \(AmneziaBackend.executablePath))")
let backendAccount = BackendAccount.current
if backendAccount.name == BackendAccount.preferredName {
    log("backends run as \(backendAccount.name) (uid \(backendAccount.uid))")
} else {
    log("! account \(BackendAccount.preferredName) is missing (reinstall the helper); backends run as \(backendAccount.name)")
}
do {
    try AmneziaBackend.verifyExecutable(AmneziaBackend.executablePath)
} catch {
    log("! \(error)")
}
log(OpenVPNBackend.isAvailable ? "OpenVPN backend: \(OpenVPNBackend.executablePath)" : "OpenVPN backend not installed")
log(OpenConnectBackend.isAvailable ? "OpenConnect backend: \(OpenConnectBackend.executablePath)" : "OpenConnect backend not installed")
log(XrayBackend.isAvailable ? "Xray backend (VLESS, Trojan, Hysteria 2): \(XrayBackend.executablePath)" : "Xray backend not installed")

let manager = TunnelManager()
manager.queue.sync { manager.firewall.recover() }
let networkMonitor = NetworkMonitor { manager.queue.async { manager.networkChanged() } }
// OpenVPN tunnels learn their interface and routes asynchronously (route-up hook).
OpenVPNRegistry.shared.onRoutesChanged = {
    manager.queue.async {
        manager.ensureServerPins()
        manager.updateFirewall()
    }
}
OpenConnectRegistry.shared.onChanged = { manager.queue.async { manager.openConnectChanged() } }
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
    // Unprivileged backends may only report hook events; they never control tunnels.
    let fromBackend = uid == backendAccount.uid
    func reply(_ response: HelperResponse) {
        guard let data = try? JSONEncoder.bridge.encode(response) else { return }
        try? UnixSocket.writeAll(fd, String(decoding: data, as: UTF8.self) + "\n")
    }
    guard authorized || fromBackend else {
        log("rejected request from uid \(uid) (not an administrator)")
        reply(.failure("Only administrators can control tunnels"))
        return
    }

    guard let line = try? UnixSocket.read(fd, until: "\n", limit: 1 << 20),
          let request = try? JSONDecoder.bridge.decode(HelperRequest.self, from: Data(line.utf8)) else {
        reply(.failure("Malformed request"))
        return
    }
    if fromBackend && request.command != .openconnectEvent && request.command != .openvpnEvent {
        reply(.failure("Not allowed"))
        return
    }
    if request.command == .ping {
        // Answered without the manager queue so clients don't time out while a tunnel connects.
        var response = HelperResponse(ok: true, capabilities: manager.capabilities)
        response.helperBuild = installedBuild
        response.requireAuthorization = HelperSettings.current.requireAuthorization
        reply(response)
        return
    }
    // Tunnel changes need the user's password when asked for; changing that setting always does.
    if HelperRequest.protectedCommands.contains(request.command), uid != 0,
       HelperSettings.current.requireAuthorization || request.command == .setRequireAuthorization {
        guard ControlAuthorization.isValid(request.authorization) else {
            reply(.failure("Bridge asks for your password before changing tunnels", code: .authorizationRequired))
            return
        }
    }
    if request.command == .setRequireAuthorization {
        guard let flag = request.flag else {
            reply(.failure("No value"))
            return
        }
        var settings = HelperSettings.current
        settings.requireAuthorization = flag
        do {
            try HelperSettings.save(settings)
            log("password before tunnel changes: \(flag ? "on" : "off") (uid \(uid))")
            reply(HelperResponse(ok: true))
        } catch {
            reply(.failure("Could not save the setting: \(error)"))
        }
        return
    }
    if request.command == .openconnectEvent {
        guard uid == 0 || fromBackend, let reason = request.event else {
            reply(.failure("Not allowed"))
            return
        }
        reply(OpenConnectRegistry.shared.handleEvent(tunnel: request.name, reason: reason,
                                                     environment: request.environment ?? [:],
                                                     peerPID: PeerAuth.peerPID(fd: fd)))
        return
    }
    if request.command == .openvpnEvent {
        // Comes from OpenVPN while `up` may still hold the manager queue.
        guard uid == 0 || fromBackend, let event = request.event else {
            reply(.failure("Not allowed"))
            return
        }
        reply(OpenVPNRegistry.shared.handleEvent(tunnel: request.name, event: event,
                                                 environment: request.environment ?? [:],
                                                 peerPID: PeerAuth.peerPID(fd: fd)))
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

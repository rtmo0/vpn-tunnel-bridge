import BridgeCore
import Foundation

// bridge-helper: privileged daemon that brings tunnels up and down.
// Started by launchd as root (see scripts/install.sh).

setvbuf(stdout, nil, _IOLBF, 0)
signal(SIGPIPE, SIG_IGN)

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

let manager = TunnelManager()
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

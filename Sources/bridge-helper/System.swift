import Foundation

struct HelperError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

private let logLock = NSLock()
private let timestampFormatter: DateFormatter = {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    return f
}()

/// Logs to stdout (launchd redirects it to /var/log/bridge/helper.log).
/// Never pass secrets to this function.
func log(_ message: String) {
    logLock.lock()
    defer { logLock.unlock() }
    print("\(timestampFormatter.string(from: Date())) \(message)")
    fflush(stdout)
}

struct CommandResult {
    let status: Int32
    let output: String
    var succeeded: Bool { status == 0 }
}

/// Runs a system tool and captures its combined output.
@discardableResult
func run(_ path: String, _ arguments: [String]) -> CommandResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    process.standardInput = FileHandle.nullDevice
    do {
        try process.run()
    } catch {
        return CommandResult(status: -1, output: "\(error)")
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return CommandResult(status: process.terminationStatus, output: String(decoding: data, as: UTF8.self))
}

/// Runs a command, logging it, and throws if it fails.
func runChecked(_ path: String, _ arguments: [String]) throws {
    let result = run(path, arguments)
    let command = ([URL(fileURLWithPath: path).lastPathComponent] + arguments).joined(separator: " ")
    if result.succeeded {
        log("  $ \(command)")
    } else {
        let output = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        log("  $ \(command) -> exit \(result.status): \(output)")
        throw HelperError("'\(command)' failed: \(output)")
    }
}

/// Path of a running process, used to make sure a recorded PID still belongs to our backend.
func executablePath(of pid: Int32) -> String? {
    var buffer = [CChar](repeating: 0, count: 4096)
    let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
    guard length > 0 else { return nil }
    return String(cString: buffer)
}

func isProcessAlive(_ pid: Int32) -> Bool {
    kill(pid, 0) == 0 || errno == EPERM
}

/// Sends SIGTERM, then SIGKILL if the process does not exit in time.
func terminate(pid: Int32, grace: TimeInterval = 2) {
    guard pid > 0, isProcessAlive(pid) else { return }
    kill(pid, SIGTERM)
    let deadline = Date().addingTimeInterval(grace)
    while Date() < deadline {
        if !isProcessAlive(pid) { return }
        usleep(50_000)
    }
    kill(pid, SIGKILL)
}

func flushDNSCache() {
    run("/usr/bin/dscacheutil", ["-flushcache"])
    run("/usr/bin/killall", ["-HUP", "mDNSResponder"])
}

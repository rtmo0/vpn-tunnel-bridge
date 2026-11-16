import Darwin
import Foundation

// Privilege separation: the helper does the root-only work (creating utun
// interfaces, addresses, routes, firewall, DNS) and runs the protocol backends,
// which talk to remote servers, as an unprivileged account.

/// The account backends run as. The installer creates `_bridge`; `nobody` is the fallback.
struct BackendAccount: Equatable {
    let uid: uid_t
    let gid: gid_t
    let name: String

    static let preferredName = "_bridge"

    static let current: BackendAccount = {
        for name in [preferredName, "nobody"] {
            if let entry = getpwnam(name), entry.pointee.pw_uid != 0, entry.pointee.pw_gid != 0 {
                return BackendAccount(uid: entry.pointee.pw_uid, gid: entry.pointee.pw_gid, name: name)
            }
        }
        // nobody is uid/gid -2 on macOS.
        return BackendAccount(uid: uid_t(bitPattern: -2), gid: gid_t(bitPattern: -2), name: "nobody")
    }()
}

/// `bridge-helper drop-exec <uid> <gid> <executable> [args…]`: the helper spawns backends
/// through itself in this mode; it gives up root for good and execs the backend.
/// File descriptors set up by the spawner (stdio, utun, UAPI socket) survive the exec.
func dropPrivilegesAndExec(_ arguments: [String]) -> Never {
    func fail(_ message: String) -> Never {
        FileHandle.standardError.write("bridge-helper drop-exec: \(message)\n".data(using: .utf8)!)
        exit(126)
    }
    guard arguments.count >= 3, let uid = uid_t(arguments[0]), let gid = gid_t(arguments[1]), uid != 0, gid != 0 else {
        fail("usage: drop-exec <uid> <gid> <executable> [args…]")
    }
    var groups = [gid]
    guard setgroups(1, &groups) == 0 else { fail("setgroups: \(String(cString: strerror(errno)))") }
    guard setgid(gid) == 0 else { fail("setgid: \(String(cString: strerror(errno)))") }
    guard setuid(uid) == 0 else { fail("setuid: \(String(cString: strerror(errno)))") }
    // Root must be gone for good.
    guard setuid(0) != 0, getuid() == uid, geteuid() == uid, getgid() == gid, getegid() == gid else {
        fail("privileges were not dropped")
    }
    signal(SIGPIPE, SIG_DFL)

    let executable = arguments[2]
    let argv: [UnsafeMutablePointer<CChar>?] = arguments.dropFirst(2).map { strdup($0) } + [nil]
    execv(executable, argv)
    fail("exec \(executable): \(String(cString: strerror(errno)))")
}

/// A child process started with `posix_spawn`, so it can inherit chosen descriptors.
final class SpawnedProcess {
    let processIdentifier: Int32
    private let lock = NSLock()
    private var exited = false
    private var source: DispatchSourceProcess?

    var isRunning: Bool { lock.withLock { !exited } }

    private init(pid: Int32) { processIdentifier = pid }

    /// - Parameters:
    ///   - account: run as this account (through `drop-exec`); nil keeps root.
    ///   - stdin, stdout, stderr: descriptors for 0, 1, 2; a negative value means /dev/null.
    ///   - inherited: descriptors the child gets as 3, 4, … (in this order).
    static func spawn(executable: String, arguments: [String], environment: [String: String],
                      account: BackendAccount?, workingDirectory: String,
                      stdin: Int32, stdout: Int32, stderr: Int32, inherited: [Int32] = [],
                      onExit: @escaping (Int32) -> Void) throws -> SpawnedProcess {
        var argvStrings = [executable] + arguments
        var path = executable
        if let account {
            path = AmneziaBackend.helperExecutablePath
            argvStrings = [path, "drop-exec", String(account.uid), String(account.gid)] + argvStrings
        }
        let argv: [UnsafeMutablePointer<CChar>?] = argvStrings.map { strdup($0) } + [nil]
        let envp: [UnsafeMutablePointer<CChar>?] = environment.sorted { $0.key < $1.key }
            .map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer {
            argv.forEach { free($0) }
            envp.forEach { free($0) }
        }

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        for (source, target) in zip([stdin, stdout, stderr] + inherited, 0...) {
            if source < 0 {
                // e.g. FileHandle.nullDevice, which has no real descriptor
                posix_spawn_file_actions_addopen(&actions, Int32(target), "/dev/null", O_RDWR, 0)
            } else if source == Int32(target) {
                posix_spawn_file_actions_addinherit_np(&actions, source)
            } else {
                posix_spawn_file_actions_adddup2(&actions, source, Int32(target))
            }
        }
        posix_spawn_file_actions_addchdir_np(&actions, workingDirectory)

        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        // Only the descriptors above reach the child; signals start out default and unblocked.
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF
                                                     | POSIX_SPAWN_SETSIGMASK))
        var all = sigset_t()
        sigfillset(&all)
        posix_spawnattr_setsigdefault(&attributes, &all)
        var none = sigset_t()
        sigemptyset(&none)
        posix_spawnattr_setsigmask(&attributes, &none)

        var pid: pid_t = 0
        let code = posix_spawn(&pid, path, &actions, &attributes, argv, envp)
        guard code == 0 else { throw HelperError("Could not start \(executable): \(String(cString: strerror(code)))") }

        let process = SpawnedProcess(pid: pid)
        let source = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: .global())
        source.setEventHandler { [weak process] in process?.reap(onExit) }
        process.source = source
        source.resume()
        // The child may have exited before the source was armed.
        process.reap(onExit, blocking: false)
        return process
    }

    private func reap(_ onExit: (Int32) -> Void, blocking: Bool = true) {
        var status: Int32 = 0
        let result = waitpid(processIdentifier, &status, blocking ? 0 : WNOHANG)
        guard result == processIdentifier || (blocking && result < 0 && errno == ECHILD) else { return }
        let first: Bool = lock.withLock {
            defer { exited = true }
            return !exited
        }
        guard first else { return }
        source?.cancel()
        onExit(processIdentifier)
    }
}

/// utun interfaces created by the helper and handed to backends as a descriptor.
enum Utun {
    // <sys/kern_control.h>, <net/if_utun.h>
    private static let ctlInfoRequest: UInt = 0xC064_4E03  // CTLIOCGINFO = _IOWR('N', 3, struct ctl_info)
    private static let utunOptionInterfaceName: Int32 = 2  // UTUN_OPT_IFNAME
    private static let controlName = "com.apple.net.utun_control"

    /// Opens utun<unit>, or the next free one if `unit` is nil. The descriptor is close-on-exec.
    static func open(unit: Int? = nil) throws -> (fd: Int32, name: String) {
        let fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
        guard fd >= 0 else { throw HelperError("Could not create a utun socket: \(String(cString: strerror(errno)))") }
        var keep = false
        defer { if !keep { close(fd) } }

        // struct ctl_info { u_int32_t ctl_id; char ctl_name[96]; }
        var info = [UInt8](repeating: 0, count: 100)
        info.replaceSubrange(4..<(4 + controlName.utf8.count), with: Array(controlName.utf8))
        guard info.withUnsafeMutableBytes({ ioctl(fd, ctlInfoRequest, $0.baseAddress!) }) == 0 else {
            throw HelperError("utun control is unavailable: \(String(cString: strerror(errno)))")
        }
        let controlID = info.withUnsafeBytes { $0.load(as: UInt32.self) }

        // struct sockaddr_ctl { u_char sc_len; u_char sc_family; u_int16_t ss_sysaddr;
        //                       u_int32_t sc_id; u_int32_t sc_unit; u_int32_t sc_reserved[5]; }
        var address = [UInt8](repeating: 0, count: 32)
        address.withUnsafeMutableBytes { raw in
            raw[0] = 32
            raw[1] = UInt8(AF_SYSTEM)
            raw.storeBytes(of: UInt16(AF_SYS_CONTROL), toByteOffset: 2, as: UInt16.self)
            raw.storeBytes(of: controlID, toByteOffset: 4, as: UInt32.self)
            raw.storeBytes(of: unit.map { UInt32($0 + 1) } ?? 0, toByteOffset: 8, as: UInt32.self)
        }
        let connected = address.withUnsafeBytes {
            Darwin.connect(fd, $0.baseAddress!.assumingMemoryBound(to: sockaddr.self), 32)
        }
        guard connected == 0 else {
            throw HelperError("Could not create \(unit.map { "utun\($0)" } ?? "a utun interface"): "
                + String(cString: strerror(errno)))
        }

        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var length = socklen_t(name.count)
        guard getsockopt(fd, SYSPROTO_CONTROL, utunOptionInterfaceName, &name, &length) == 0 else {
            throw HelperError("Could not read the utun name: \(String(cString: strerror(errno)))")
        }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        keep = true
        return (fd, String(cString: name))
    }
}

extension PeerAuth {
    private static let solLocal: Int32 = 0       // SOL_LOCAL
    private static let localPeerPID: Int32 = 2   // LOCAL_PEERPID

    /// PID of the process on the other end of a Unix socket.
    static func peerPID(fd: Int32) -> pid_t? {
        var pid: pid_t = 0
        var length = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, solLocal, localPeerPID, &pid, &length) == 0, pid > 0 else { return nil }
        return pid
    }

    static func parentPID(of pid: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return pid_t(info.pbi_ppid)
    }

    /// True if `pid` is `ancestor` or runs below it (hooks are started via /bin/sh).
    static func isProcess(_ pid: pid_t, descendantOf ancestor: pid_t, maxDepth: Int = 4) -> Bool {
        guard ancestor > 1 else { return false }
        var current = pid
        for _ in 0...maxDepth {
            if current == ancestor { return true }
            guard let parent = parentPID(of: current), parent > 1 else { return false }
            current = parent
        }
        return false
    }
}

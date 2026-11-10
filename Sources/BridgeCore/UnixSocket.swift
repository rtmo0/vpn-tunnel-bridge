import Foundation

public struct SocketError: Error, CustomStringConvertible {
    public let operation: String
    public let code: Int32

    public init(_ operation: String, code: Int32 = Foundation.errno) {
        self.operation = operation
        self.code = code
    }

    public var description: String { "\(operation): \(String(cString: strerror(code)))" }
}

/// Minimal blocking AF_UNIX stream socket helpers.
public enum UnixSocket {
    private static func makeAddress(_ path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard bytes.count < capacity else { throw SocketError("socket path too long", code: ENAMETOOLONG) }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: bytes)
            buffer[bytes.count] = 0
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return address
    }

    private static func newSocket() throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError("socket") }
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        return fd
    }

    public static func setTimeout(_ fd: Int32, seconds: Int) {
        var tv = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    public static func connect(path: String, timeout: Int = 30) throws -> Int32 {
        var address = try makeAddress(path)
        let fd = try newSocket()
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let code = Foundation.errno
            close(fd)
            throw SocketError("connect \(path)", code: code)
        }
        setTimeout(fd, seconds: timeout)
        return fd
    }

    public static func listen(path: String, mode: mode_t) throws -> Int32 {
        unlink(path)
        var address = try makeAddress(path)
        let fd = try newSocket()
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0 else {
            let code = Foundation.errno
            close(fd)
            throw SocketError("bind \(path)", code: code)
        }
        chmod(path, mode)
        guard Darwin.listen(fd, 16) == 0 else {
            let code = Foundation.errno
            close(fd)
            throw SocketError("listen", code: code)
        }
        return fd
    }

    public static func writeAll(_ fd: Int32, _ string: String) throws {
        let bytes = Array(string.utf8)
        var offset = 0
        while offset < bytes.count {
            let written = bytes[offset...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            if written < 0 {
                if Foundation.errno == EINTR { continue }
                throw SocketError("write")
            }
            offset += written
        }
    }

    /// Reads until the accumulated data ends with `terminator`, EOF, or `limit` bytes.
    public static func read(_ fd: Int32, until terminator: String, limit: Int = 4 << 20) throws -> String {
        let end = Array(terminator.utf8)
        var data = [UInt8]()
        var chunk = [UInt8](repeating: 0, count: 16384)
        while data.count < limit {
            let n = Darwin.read(fd, &chunk, chunk.count)
            if n < 0 {
                if Foundation.errno == EINTR { continue }
                throw SocketError("read")
            }
            if n == 0 { break }
            data.append(contentsOf: chunk[0..<n])
            if data.count >= end.count && Array(data.suffix(end.count)) == end { break }
        }
        guard data.count < limit else { throw SocketError("message too large", code: EMSGSIZE) }
        return String(decoding: data, as: UTF8.self)
    }
}

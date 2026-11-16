import Foundation

/// Health checks for Xray tunnels and local proxies.
///
/// Xray's TUN stack and SOCKS inbound accept every connection locally, so a TCP
/// handshake proves nothing. Instead Xray forwards a localhost port (dokodemo-door)
/// through the proxy to `ProxyLink.probeTargets`, and only a real HTTP answer counts.
public enum XrayProbe {
    /// Sends a HEAD request to the localhost forwarder on `port`.
    public static func check(port: UInt16, timeout: TimeInterval) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = loopback(port: port)
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { return false }
        let request = "HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nUser-Agent: Bridge\r\nConnection: close\r\n\r\n"
        guard request.withCString({ send(fd, $0, strlen($0), 0) }) > 0 else { return false }
        var buffer = [UInt8](repeating: 0, count: 64)
        var received = 0
        let deadline = Date().addingTimeInterval(timeout)
        while received < 5, Date() < deadline {
            let n = buffer.withUnsafeMutableBytes { recv(fd, $0.baseAddress! + received, 64 - received, 0) }
            if n <= 0 { return false }
            received += n
        }
        return received >= 5 && String(decoding: buffer[0..<5], as: UTF8.self) == "HTTP/"
    }

    /// A localhost TCP port that is free right now (the OS picks it).
    public static func freeLoopbackPort() -> UInt16? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var addr = loopback(port: 0)
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let ok = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, length) == 0 && getsockname(fd, $0, &length) == 0
            }
        }
        return ok ? UInt16(bigEndian: addr.sin_port) : nil
    }

    /// True if nothing listens on 127.0.0.1:`port` yet.
    public static func isLoopbackPortFree(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = loopback(port: port)
        return withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
    }

    private static func loopback(port: UInt16) -> sockaddr_in {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        return addr
    }
}

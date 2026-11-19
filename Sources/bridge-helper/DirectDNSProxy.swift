import BridgeCore
import Darwin
import Foundation

/// A small DNS forwarder on 127.0.0.1 for the domains of direct sites.
///
/// The system sends queries for those domains (and every subdomain) here; the proxy
/// forwards them to the physical network's DNS through the physical interface (the
/// socket is bound to it, so the tunnel is not involved and no route is needed), and
/// hands each answer's addresses to `onAnswer` before replying. That way an address is
/// routed around the tunnel before the app that asked can connect to it.
final class DirectDNSProxy {
    static let shared = DirectDNSProxy()
    static let address = "127.0.0.1"
    static let port: UInt16 = 53535

    struct Upstream: Equatable {
        var servers: [String]
        var interface: String
        /// Answer AAAA queries; otherwise they get an empty answer, so apps use IPv4.
        var allowIPv6: Bool
    }

    /// Called with the queried name and the addresses in the answer; must return once
    /// routes are in place (it may block briefly).
    var onAnswer: (String, [IPAddress]) -> Void = { _, _ in }

    private let lock = NSLock()
    private var _upstream: Upstream?
    private var started = false
    private(set) var isRunning = false
    private let work = DispatchQueue(label: "com.rtmo0.bridge.helper.dns-proxy", attributes: .concurrent)

    var upstream: Upstream? {
        get { lock.withLock { _upstream } }
        set { lock.withLock { _upstream = newValue } }
    }

    /// Starts listening (once). Returns false if the port is taken.
    @discardableResult
    func start() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if started { return isRunning }
        started = true
        guard let udp = listen(type: SOCK_DGRAM), let tcp = listen(type: SOCK_STREAM) else {
            log("! DNS proxy for direct sites could not listen on \(Self.address):\(Self.port)")
            return false
        }
        isRunning = true
        Thread { [weak self] in self?.serveUDP(udp) }.start()
        Thread { [weak self] in self?.serveTCP(tcp) }.start()
        log("DNS proxy for direct sites listening on \(Self.address):\(Self.port)")
        return true
    }

    private func listen(type: Int32) -> Int32? {
        let fd = socket(AF_INET, type, 0)
        guard fd >= 0 else { return nil }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = Self.port.bigEndian
        addr.sin_addr.s_addr = inet_addr(Self.address)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0, type == SOCK_DGRAM || Darwin.listen(fd, 16) == 0 else {
            close(fd)
            return nil
        }
        return fd
    }

    // MARK: Serving

    private func serveUDP(_ fd: Int32) {
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            var client = sockaddr_storage()
            var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &client) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buffer, buffer.count, 0, $0, &length) }
            }
            if n <= 0 { continue }
            let query = Array(buffer[0..<n])
            work.async { [weak self] in
                guard let self, let reply = self.answer(query, tcp: false) else { return }
                var client = client
                _ = withUnsafePointer(to: &client) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, reply, reply.count, 0, $0, length) }
                }
            }
        }
    }

    private func serveTCP(_ fd: Int32) {
        while true {
            let client = accept(fd, nil, nil)
            if client < 0 { continue }
            work.async { [weak self] in
                defer { close(client) }
                Self.setTimeout(client, seconds: 10)
                while let query = Self.readFramed(client), let self, let reply = self.answer(query, tcp: true) {
                    guard Self.writeFramed(client, reply) else { return }
                }
            }
        }
    }

    /// The reply for one query: forwarded upstream, or an empty answer for AAAA.
    private func answer(_ query: [UInt8], tcp: Bool) -> [UInt8]? {
        guard let question = DNSMessage.question(query) else { return nil }
        guard let upstream else { return DNSMessage.failure(query) }
        if question.type == 28 && !upstream.allowIPv6 { return DNSMessage.emptyAnswer(query) }
        for server in upstream.servers {
            guard let reply = Self.forward(query, to: server, interface: upstream.interface, tcp: tcp),
                  reply.count >= 12, reply[0] == query[0], reply[1] == query[1] else { continue }
            let addresses = DNSMessage.addresses(reply)
            if !addresses.isEmpty { onAnswer(question.name, addresses) }
            return reply
        }
        return DNSMessage.failure(query)
    }

    // MARK: Upstream

    private static func forward(_ query: [UInt8], to server: String, interface: String, tcp: Bool) -> [UInt8]? {
        guard let ip = IPAddress(server) else { return nil }
        let family = ip.isIPv6 ? AF_INET6 : AF_INET
        let fd = socket(family, tcp ? SOCK_STREAM : SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var index = if_nametoindex(interface)
        guard index != 0 else { return nil }
        if ip.isIPv6 {
            setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &index, socklen_t(MemoryLayout<UInt32>.size))
        } else {
            setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, socklen_t(MemoryLayout<UInt32>.size))
        }
        setTimeout(fd, seconds: tcp ? 5 : 2)

        var storage = sockaddr_storage()
        let length: socklen_t
        if ip.isIPv6 {
            var addr = sockaddr_in6()
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = UInt16(53).bigEndian
            withUnsafeMutableBytes(of: &addr.sin6_addr) { $0.copyBytes(from: ip.bytes) }
            withUnsafeMutableBytes(of: &storage) { dst in withUnsafeBytes(of: addr) { dst.copyMemory(from: $0) } }
            length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        } else {
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = UInt16(53).bigEndian
            withUnsafeMutableBytes(of: &addr.sin_addr) { $0.copyBytes(from: ip.bytes) }
            withUnsafeMutableBytes(of: &storage) { dst in withUnsafeBytes(of: addr) { dst.copyMemory(from: $0) } }
            length = socklen_t(MemoryLayout<sockaddr_in>.size)
        }
        let connected = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, length) }
        }
        guard connected == 0 else { return nil }
        if tcp {
            guard writeFramed(fd, query) else { return nil }
            return readFramed(fd)
        }
        guard send(fd, query, query.count, 0) == query.count else { return nil }
        var buffer = [UInt8](repeating: 0, count: 65535)
        let n = recv(fd, &buffer, buffer.count, 0)
        return n > 0 ? Array(buffer[0..<n]) : nil
    }

    private static func setTimeout(_ fd: Int32, seconds: Int) {
        var timeout = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    }

    private static func readExactly(_ fd: Int32, _ count: Int) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = out.withUnsafeMutableBytes { recv(fd, $0.baseAddress! + got, count - got, 0) }
            if n <= 0 { return nil }
            got += n
        }
        return out
    }

    private static func readFramed(_ fd: Int32) -> [UInt8]? {
        guard let header = readExactly(fd, 2) else { return nil }
        let length = Int(header[0]) << 8 | Int(header[1])
        return length > 0 ? readExactly(fd, length) : nil
    }

    private static func writeFramed(_ fd: Int32, _ message: [UInt8]) -> Bool {
        let framed = [UInt8(message.count >> 8), UInt8(message.count & 0xFF)] + message
        var sent = 0
        while sent < framed.count {
            let n = framed.withUnsafeBytes { send(fd, $0.baseAddress! + sent, framed.count - sent, 0) }
            if n <= 0 { return false }
            sent += n
        }
        return true
    }
}

/// Just enough of the DNS wire format: the question, the addresses in the answer,
/// and two synthetic replies.
enum DNSMessage {
    struct Question {
        var name: String
        var type: UInt16
    }

    static func question(_ m: [UInt8]) -> Question? {
        guard m.count >= 12, m[2] & 0x80 == 0, (Int(m[4]) << 8 | Int(m[5])) == 1 else { return nil }
        var i = 12
        var labels: [String] = []
        while i < m.count {
            let length = Int(m[i])
            if length == 0 { i += 1; break }
            guard length < 64, i + 1 + length <= m.count else { return nil }
            labels.append(String(decoding: m[(i + 1)...(i + length)], as: UTF8.self).lowercased())
            i += 1 + length
        }
        guard i + 4 <= m.count else { return nil }
        return Question(name: labels.joined(separator: "."), type: UInt16(m[i]) << 8 | UInt16(m[i + 1]))
    }

    /// Skips a possibly compressed name; returns the offset after it.
    private static func skipName(_ m: [UInt8], _ start: Int) -> Int? {
        var i = start
        while i < m.count {
            let length = Int(m[i])
            if length == 0 { return i + 1 }
            if length & 0xC0 == 0xC0 { return i + 2 <= m.count ? i + 2 : nil }
            i += 1 + length
        }
        return nil
    }

    /// A and AAAA records in the answer section (CNAME targets included).
    static func addresses(_ m: [UInt8]) -> [IPAddress] {
        guard m.count >= 12, m[3] & 0x0F == 0 else { return [] }
        let questions = Int(m[4]) << 8 | Int(m[5])
        let answers = Int(m[6]) << 8 | Int(m[7])
        var i = 12
        for _ in 0..<questions {
            guard let next = skipName(m, i), next + 4 <= m.count else { return [] }
            i = next + 4
        }
        var out: [IPAddress] = []
        for _ in 0..<answers {
            guard let next = skipName(m, i), next + 10 <= m.count else { break }
            let type = Int(m[next]) << 8 | Int(m[next + 1])
            let length = Int(m[next + 8]) << 8 | Int(m[next + 9])
            let data = next + 10
            guard data + length <= m.count else { break }
            if (type == 1 && length == 4) || (type == 28 && length == 16) {
                let text = type == 1
                    ? m[data..<data + 4].map(String.init).joined(separator: ".")
                    : stride(from: data, to: data + 16, by: 2).map { String(format: "%x", Int(m[$0]) << 8 | Int(m[$0 + 1])) }
                        .joined(separator: ":")
                if let ip = IPAddress(text), !out.contains(ip) { out.append(ip) }
            }
            i = data + length
        }
        return out
    }

    /// The query turned into a reply with no records (NOERROR / NODATA).
    static func emptyAnswer(_ query: [UInt8]) -> [UInt8] { reply(query, rcode: 0) }

    /// SERVFAIL, so the client tries again or gives up quickly.
    static func failure(_ query: [UInt8]) -> [UInt8] { reply(query, rcode: 2) }

    private static func reply(_ query: [UInt8], rcode: UInt8) -> [UInt8] {
        guard query.count >= 12, let end = skipName(query, 12), end + 4 <= query.count else { return [] }
        var out = Array(query[0..<(end + 4)])
        out[2] = 0x80 | (query[2] & 0x79)  // QR, keep opcode and RD
        out[3] = 0x80 | rcode              // RA
        out[4] = 0; out[5] = 1             // one question
        for k in 6..<12 { out[k] = 0 }     // no answer, authority or additional records
        return out
    }
}

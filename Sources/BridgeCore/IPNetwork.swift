import Foundation

/// An IPv4 or IPv6 address, stored as raw network-order bytes.
public struct IPAddress: Hashable, Sendable, CustomStringConvertible {
    public let bytes: [UInt8]

    public var isIPv6: Bool { bytes.count == 16 }

    init(bytes: [UInt8]) {
        precondition(bytes.count == 4 || bytes.count == 16)
        self.bytes = bytes
    }

    public init?(_ string: String) {
        var trimmed = string.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
            trimmed = String(trimmed.dropFirst().dropLast())
        }
        var v4 = in_addr()
        if inet_pton(AF_INET, trimmed, &v4) == 1 {
            bytes = withUnsafeBytes(of: &v4) { Array($0) }
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, trimmed, &v6) == 1 {
            bytes = withUnsafeBytes(of: &v6) { Array($0) }
            return
        }
        return nil
    }

    public var description: String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let family = isIPv6 ? AF_INET6 : AF_INET
        let result = bytes.withUnsafeBytes { raw in
            inet_ntop(family, raw.baseAddress, &buffer, socklen_t(buffer.count))
        }
        guard result != nil else { return "?" }
        return String(cString: buffer)
    }
}

/// An address with a prefix length, e.g. `10.9.9.6/32` or `::/0`.
public struct IPNetwork: Hashable, Sendable, CustomStringConvertible {
    public let address: IPAddress
    public let prefix: Int

    public var isIPv6: Bool { address.isIPv6 }
    public var maxPrefix: Int { isIPv6 ? 128 : 32 }
    public var isDefaultRoute: Bool { prefix == 0 }

    public init(address: IPAddress, prefix: Int) {
        self.address = address
        self.prefix = prefix
    }

    public init?(_ string: String) {
        let parts = string.trimmingCharacters(in: .whitespaces).split(separator: "/", maxSplits: 1)
        guard let first = parts.first, let address = IPAddress(String(first)) else { return nil }
        let max = address.isIPv6 ? 128 : 32
        if parts.count == 2 {
            guard let prefix = Int(parts[1]), (0...max).contains(prefix) else { return nil }
            self.init(address: address, prefix: prefix)
        } else {
            self.init(address: address, prefix: max)
        }
    }

    /// Whether `ip` falls inside this network.
    public func contains(_ ip: IPAddress) -> Bool {
        guard ip.isIPv6 == isIPv6 else { return false }
        var remaining = prefix
        for i in 0..<address.bytes.count {
            if remaining <= 0 { return true }
            let bits = min(8, remaining)
            let mask: UInt8 = bits == 8 ? 0xFF : ~(0xFF >> UInt8(bits))
            if address.bytes[i] & mask != ip.bytes[i] & mask { return false }
            remaining -= bits
        }
        return true
    }

    /// The network with host bits cleared, as `route(8)` expects.
    public var masked: IPNetwork {
        var out = address.bytes
        var remaining = prefix
        for i in 0..<out.count {
            let bits = max(0, min(8, remaining))
            let mask: UInt8 = bits == 8 ? 0xFF : (bits == 0 ? 0 : ~(0xFF >> UInt8(bits)))
            out[i] &= mask
            remaining -= 8
        }
        return IPNetwork(address: IPAddress(bytes: out), prefix: prefix)
    }

    public var description: String { "\(address)/\(prefix)" }
}

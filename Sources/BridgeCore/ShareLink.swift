import Foundation

/// The parts of a share link such as `vless://id@host:443?type=ws#name`.
///
/// Parsed by hand rather than with URLComponents: Hysteria links put several
/// ports in the authority (`host:443,20000-30000`), which is not a URL port.
struct ShareLink {
    var scheme: String
    /// Percent-decoded user info (UUID, password, or `user:pass`).
    var user: String?
    var host: String
    /// The port part as written, e.g. `443` or `443,20000-30000`; nil when absent.
    var portSpec: String?
    var fragment: String?
    /// Query parameters, percent-decoded. Empty values are kept as "".
    private(set) var params: [String: String] = [:]

    static func parse(_ text: String) throws -> ShareLink {
        let link = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !link.contains(where: \.isNewline) else {
            throw ConfigError("Expected one link; import several links as separate tunnels")
        }
        guard let schemeEnd = link.range(of: "://") else { throw ConfigError("Not a share link") }
        let scheme = link[..<schemeEnd.lowerBound].lowercased()
        var rest = Substring(link[schemeEnd.upperBound...])

        var fragment: String?
        if let hash = rest.firstIndex(of: "#") {
            let raw = String(rest[rest.index(after: hash)...])
            fragment = raw.removingPercentEncoding ?? raw
            rest = rest[..<hash]
        }
        var query: Substring = ""
        if let mark = rest.firstIndex(of: "?") {
            query = rest[rest.index(after: mark)...]
            rest = rest[..<mark]
        }
        if let slash = rest.firstIndex(of: "/") {
            guard rest[slash...].allSatisfy({ $0 == "/" }) else {
                throw ConfigError("Unexpected path “\(rest[slash...])” in the link")
            }
            rest = rest[..<slash]
        }

        var user: String?
        if let at = rest.lastIndex(of: "@") {
            guard let decoded = String(rest[..<at]).removingPercentEncoding else {
                throw ConfigError("The user part of the link is not valid percent-encoding")
            }
            user = decoded
            rest = rest[rest.index(after: at)...]
        }

        var host: String
        var portSpec: String?
        if rest.hasPrefix("[") {
            guard let close = rest.firstIndex(of: "]") else { throw ConfigError("Unclosed “[” in the server address") }
            host = String(rest[rest.index(after: rest.startIndex)..<close])
            let after = rest[rest.index(after: close)...]
            if !after.isEmpty {
                guard after.hasPrefix(":") else { throw ConfigError("Unexpected “\(after)” after the server address") }
                portSpec = String(after.dropFirst())
            }
        } else if let colon = rest.firstIndex(of: ":") {
            host = String(rest[..<colon])
            portSpec = String(rest[rest.index(after: colon)...])
        } else {
            host = String(rest)
        }
        host = host.removingPercentEncoding ?? host
        guard !host.isEmpty else { throw ConfigError("The link has no server address") }
        guard host.allSatisfy({ !$0.isWhitespace && $0 != "\"" && $0 != "\\" }) else {
            throw ConfigError("The server address “\(host)” is not valid")
        }

        var parts = ShareLink(scheme: scheme, user: user, host: host, portSpec: portSpec,
                              fragment: fragment.flatMap { $0.isEmpty ? nil : $0 })
        // URLComponents decodes the query correctly ("+" stays "+", as base64 values need).
        if !query.isEmpty {
            guard let items = URLComponents(string: "x://h/?\(query)")?.queryItems else {
                throw ConfigError("The parameters of the link are malformed")
            }
            for item in items where !item.name.isEmpty {
                guard parts.params[item.name] == nil else { throw ConfigError("Parameter “\(item.name)” appears twice") }
                parts.params[item.name] = item.value ?? ""
            }
        }
        return parts
    }

    /// A single port (1–65535) from `portSpec`.
    func singlePort(default fallback: UInt16? = nil) throws -> UInt16 {
        guard let portSpec, !portSpec.isEmpty else {
            if let fallback { return fallback }
            throw ConfigError("The link has no server port (\(scheme)://…@\(host):<port>)")
        }
        guard let port = UInt16(portSpec), port > 0 else { throw ConfigError("“\(portSpec)” is not a port") }
        return port
    }

    /// Removes and returns a parameter; empty values count as absent, because
    /// panels routinely emit `host=&path=`.
    mutating func take(_ name: String) -> String? {
        guard let value = params.removeValue(forKey: name) else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Fails on the first parameter nobody took.
    func rejectLeftovers() throws {
        if let unknown = params.keys.sorted().first {
            throw ConfigError("Unknown parameter “\(unknown)” in the link")
        }
    }
}

/// A list of ports and port ranges, e.g. `443,20000-30000` (Hysteria port hopping).
public struct PortList: Equatable, Sendable, CustomStringConvertible {
    public var ranges: [ClosedRange<UInt16>]

    public init?(_ text: String) {
        var ranges: [ClosedRange<UInt16>] = []
        for part in text.split(separator: ",") {
            let item = part.trimmingCharacters(in: .whitespaces)
            let bounds = item.split(separator: "-", omittingEmptySubsequences: false)
            guard (1...2).contains(bounds.count),
                  let low = UInt16(bounds[0]), let high = UInt16(bounds.last!), low > 0, low <= high else { return nil }
            ranges.append(low...high)
        }
        guard !ranges.isEmpty else { return nil }
        self.ranges = ranges
    }

    public var first: UInt16 { ranges[0].lowerBound }
    public var isSinglePort: Bool { ranges.count == 1 && ranges[0].count == 1 }

    public var description: String {
        ranges.map { $0.count == 1 ? "\($0.lowerBound)" : "\($0.lowerBound)-\($0.upperBound)" }.joined(separator: ",")
    }
}

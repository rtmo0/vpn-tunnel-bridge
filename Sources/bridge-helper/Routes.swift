import BridgeCore
import Foundation

/// A route added by Bridge, recorded so it can be removed later.
struct RouteEntry: Codable, Hashable, CustomStringConvertible {
    var destination: String  // e.g. "0.0.0.0/1", "203.0.113.7"
    var ipv6: Bool
    var gateway: String?
    var interface: String?

    var familyFlag: String { ipv6 ? "-inet6" : "-inet" }

    var arguments: [String] {
        var args = [familyFlag, destination]
        if let gateway {
            args.append(gateway)
        } else if let interface {
            args += ["-interface", interface]
        }
        return args
    }

    var description: String {
        destination + (gateway.map { " via \($0)" } ?? "") + (interface.map { " dev \($0)" } ?? "")
    }
}

enum Routes {
    private static let route = "/sbin/route"

    struct Lookup {
        var gateway: String?
        var interface: String?
    }

    /// Asks the kernel how `destination` ("default" or an IP) is reached right now.
    static func lookup(_ destination: String, ipv6: Bool) -> Lookup? {
        let result = run(route, ["-n", "get", ipv6 ? "-inet6" : "-inet", destination])
        guard result.succeeded else { return nil }
        var lookup = Lookup()
        for line in result.output.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            switch parts[0] {
            case "gateway": lookup.gateway = parts[1]
            case "interface": lookup.interface = parts[1]
            default: break
            }
        }
        // "link#14" or a MAC address means a directly connected network: route via the interface.
        if let gateway = lookup.gateway, IPAddress(gateway.split(separator: "%").first.map(String.init) ?? "") == nil {
            lookup.gateway = nil
        }
        guard lookup.gateway != nil || lookup.interface != nil else { return nil }
        return lookup
    }

    /// The default route outside Bridge's own tunnels (Wi-Fi, Ethernet, or another VPN).
    static func uplink(excluding interfaces: Set<String>) -> Lookup? {
        let result = run("/usr/sbin/netstat", ["-rn", "-f", "inet"])
        guard result.succeeded else { return nil }
        for line in result.output.split(separator: "\n") {
            let cols = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard cols.count >= 4, cols[0] == "default", let interface = cols.last,
                  !interfaces.contains(interface) else { continue }
            let gateway = IPAddress(cols[1]) != nil ? cols[1] : nil
            return Lookup(gateway: gateway, interface: interface)
        }
        return nil
    }

    /// Adds a route. Returns false if an identical route already existed (so we don't own it).
    @discardableResult
    static func add(_ entry: RouteEntry) throws -> Bool {
        let result = run(route, ["-q", "-n", "add"] + entry.arguments)
        if result.succeeded {
            log("  + route \(entry)")
            return true
        }
        if result.output.contains("File exists") {
            log("  = route \(entry) already exists, leaving it alone")
            return false
        }
        throw HelperError("Could not add route \(entry): \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))")
    }

    static func delete(_ entry: RouteEntry) {
        let result = run(route, ["-q", "-n", "delete"] + entry.arguments)
        if result.succeeded {
            log("  - route \(entry)")
        }
    }

    /// Splits a default route into two halves so it wins over the system default
    /// without replacing it (the same trick wg-quick uses).
    static func tunnelRoutes(for network: IPNetwork, interface: String) -> [RouteEntry] {
        let net = network.masked
        if net.isDefaultRoute {
            let halves = net.isIPv6 ? ["::/1", "8000::/1"] : ["0.0.0.0/1", "128.0.0.0/1"]
            return halves.map { RouteEntry(destination: $0, ipv6: net.isIPv6, gateway: nil, interface: interface) }
        }
        let destination = net.prefix == net.maxPrefix ? "\(net.address)" : net.description
        return [RouteEntry(destination: destination, ipv6: net.isIPv6, gateway: nil, interface: interface)]
    }
}

enum Interface {
    private static let ifconfig = "/sbin/ifconfig"

    static func mtu(of name: String) -> Int? {
        let result = run(ifconfig, [name])
        guard result.succeeded, let range = result.output.range(of: "mtu ") else { return nil }
        let digits = result.output[range.upperBound...].prefix { $0.isNumber }
        return Int(digits)
    }

    static func configure(_ name: String, addresses: [IPNetwork], mtu: Int) throws {
        for address in addresses {
            if address.isIPv6 {
                try runChecked(ifconfig, [name, "inet6", address.description, "alias"])
            } else {
                // utun is point-to-point: the destination is the address itself, like wg-quick.
                try runChecked(ifconfig, [name, "inet", address.description, "\(address.address)", "alias"])
            }
        }
        try runChecked(ifconfig, [name, "mtu", String(mtu)])
        try runChecked(ifconfig, [name, "up"])
    }
}

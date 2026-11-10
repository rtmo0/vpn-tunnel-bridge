import BridgeCore
import Foundation
import SystemConfiguration

struct DNSSettings {
    var servers: [String]
    var searchDomains: [String]
    var fullTunnel: Bool
    var interface: String
    var ipv4Addresses: [String]
    var ipv6Addresses: [(address: String, prefix: Int)]

    init(servers: [String], searchDomains: [String], fullTunnel: Bool, interface: String,
         ipv4Addresses: [String], ipv6Addresses: [(address: String, prefix: Int)]) {
        self.servers = servers
        self.searchDomains = searchDomains
        self.fullTunnel = fullTunnel
        self.interface = interface
        self.ipv4Addresses = ipv4Addresses
        self.ipv6Addresses = ipv6Addresses
    }

    init(config: TunnelConfig, interface: String) {
        self.init(servers: config.dnsServers.map(\.description), searchDomains: config.dnsSearchDomains,
                  fullTunnel: config.isFullTunnel, interface: interface,
                  ipv4Addresses: config.addresses.filter { !$0.isIPv6 }.map { "\($0.address)" },
                  ipv6Addresses: config.addresses.filter(\.isIPv6).map { ("\($0.address)", $0.prefix) })
    }
}

/// Publishes tunnel DNS settings into the System Configuration dynamic store.
///
/// Values are added as *temporary* keys of this helper's session, so configd
/// removes them automatically if the helper crashes: DNS can never be left
/// pointing at a dead tunnel. Thread-safe.
final class DNSManager {
    static let shared = DNSManager()

    private let store: SCDynamicStore
    private let lock = NSLock()
    private var active: [String: [String]] = [:]

    private init() {
        guard let store = SCDynamicStoreCreate(nil, HelperProtocol.launchdLabel as CFString, nil, nil) else {
            fatalError("SCDynamicStoreCreate failed: \(String(cString: SCErrorString(SCError())))")
        }
        self.store = store
    }

    func servers(for tunnel: String) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return active[tunnel] ?? []
    }

    /// Returns a warning when DNS cannot be applied meaningfully.
    func apply(tunnel: String, _ settings: DNSSettings) -> String? {
        guard !settings.servers.isEmpty else { return nil }
        if !settings.fullTunnel && settings.searchDomains.isEmpty {
            return "DNS servers are set, but this tunnel only carries some networks and has no search domains, "
                + "so macOS keeps using its own DNS."
        }

        lock.lock()
        defer { lock.unlock() }
        removeLocked(tunnel: tunnel, flush: false)

        let base = "State:/Network/Service/Bridge-\(tunnel)"
        var dns: [String: Any] = ["ServerAddresses": settings.servers]
        if !settings.searchDomains.isEmpty {
            dns["SearchDomains"] = settings.searchDomains
            dns["DomainName"] = settings.searchDomains[0]
            if !settings.fullTunnel { dns["SupplementalMatchDomains"] = settings.searchDomains }
        }
        if !settings.ipv4Addresses.isEmpty {
            var ipv4: [String: Any] = [
                "Addresses": settings.ipv4Addresses,
                "SubnetMasks": settings.ipv4Addresses.map { _ in "255.255.255.255" },
                "InterfaceName": settings.interface,
            ]
            if settings.fullTunnel {
                ipv4["Router"] = settings.ipv4Addresses[0]
                ipv4["OverridePrimary"] = 1
            }
            add("\(base)/IPv4", ipv4)
        }
        if !settings.ipv6Addresses.isEmpty {
            var ipv6: [String: Any] = [
                "Addresses": settings.ipv6Addresses.map(\.address),
                "PrefixLength": settings.ipv6Addresses.map(\.prefix),
                "InterfaceName": settings.interface,
            ]
            if settings.fullTunnel {
                ipv6["Router"] = settings.ipv6Addresses[0].address
                ipv6["OverridePrimary"] = 1
            }
            add("\(base)/IPv6", ipv6)
        }
        add("\(base)/DNS", dns)
        active[tunnel] = settings.servers
        log("  DNS \(settings.servers.joined(separator: ", "))"
            + (settings.fullTunnel ? " (primary)" : " for \(settings.searchDomains.joined(separator: ", "))"))
        flushDNSCache()
        return nil
    }

    func remove(tunnel: String) {
        lock.lock()
        defer { lock.unlock() }
        removeLocked(tunnel: tunnel, flush: true)
    }

    private func removeLocked(tunnel: String, flush: Bool) {
        let base = "State:/Network/Service/Bridge-\(tunnel)"
        var removed = false
        for key in ["\(base)/DNS", "\(base)/IPv4", "\(base)/IPv6"] where SCDynamicStoreCopyValue(store, key as CFString) != nil {
            SCDynamicStoreRemoveValue(store, key as CFString)
            removed = true
        }
        active[tunnel] = nil
        if removed {
            log("  DNS settings of '\(tunnel)' removed")
            if flush { flushDNSCache() }
        }
    }

    private func add(_ key: String, _ value: [String: Any]) {
        if !SCDynamicStoreAddTemporaryValue(store, key as CFString, value as CFDictionary) {
            log("  ! could not publish \(key): \(String(cString: SCErrorString(SCError())))")
        }
    }
}

import BridgeCore
import Foundation
import SystemConfiguration

/// Publishes tunnel DNS settings into the System Configuration dynamic store.
///
/// Values are added as *temporary* keys of this helper's session, so configd
/// removes them automatically if the helper crashes: DNS can never be left
/// pointing at a dead tunnel.
final class DNSManager {
    private let store: SCDynamicStore

    init() {
        guard let store = SCDynamicStoreCreate(nil, HelperProtocol.launchdLabel as CFString, nil, nil) else {
            fatalError("SCDynamicStoreCreate failed: \(String(cString: SCErrorString(SCError())))")
        }
        self.store = store
    }

    private func serviceKeys(for tunnel: String) -> (ipv4: String, ipv6: String, dns: String) {
        let base = "State:/Network/Service/Bridge-\(tunnel)"
        return ("\(base)/IPv4", "\(base)/IPv6", "\(base)/DNS")
    }

    /// Returns a warning when DNS cannot be applied meaningfully.
    func apply(tunnel: String, interface: String, config: TunnelConfig) -> String? {
        guard !config.dnsServers.isEmpty else { return nil }

        let full = config.isFullTunnel
        if !full && config.dnsSearchDomains.isEmpty {
            return "DNS servers are set, but this is a split tunnel without search domains, "
                + "so the system will keep using its own DNS."
        }

        let keys = serviceKeys(for: tunnel)
        remove(tunnel: tunnel)

        var dns: [String: Any] = ["ServerAddresses": config.dnsServers.map(\.description)]
        if !config.dnsSearchDomains.isEmpty {
            dns["SearchDomains"] = config.dnsSearchDomains
            dns["DomainName"] = config.dnsSearchDomains[0]
            if !full { dns["SupplementalMatchDomains"] = config.dnsSearchDomains }
        }

        let v4 = config.addresses.filter { !$0.isIPv6 }
        if !v4.isEmpty {
            var ipv4: [String: Any] = [
                "Addresses": v4.map { "\($0.address)" },
                "SubnetMasks": v4.map { _ in "255.255.255.255" },
                "InterfaceName": interface,
            ]
            if full {
                ipv4["Router"] = "\(v4[0].address)"
                ipv4["OverridePrimary"] = 1
            }
            add(keys.ipv4, ipv4)
        }
        let v6 = config.addresses.filter(\.isIPv6)
        if !v6.isEmpty {
            var ipv6: [String: Any] = [
                "Addresses": v6.map { "\($0.address)" },
                "PrefixLength": v6.map(\.prefix),
                "InterfaceName": interface,
            ]
            if full {
                ipv6["Router"] = "\(v6[0].address)"
                ipv6["OverridePrimary"] = 1
            }
            add(keys.ipv6, ipv6)
        }
        add(keys.dns, dns)
        log("  DNS \(config.dnsServers.map(\.description).joined(separator: ", "))"
            + (full ? " (primary)" : " for \(config.dnsSearchDomains.joined(separator: ", "))"))
        flushDNSCache()
        return nil
    }

    func remove(tunnel: String) {
        let keys = serviceKeys(for: tunnel)
        var removed = false
        for key in [keys.dns, keys.ipv4, keys.ipv6] {
            if SCDynamicStoreCopyValue(store, key as CFString) != nil {
                SCDynamicStoreRemoveValue(store, key as CFString)
                removed = true
            }
        }
        if removed {
            log("  DNS settings of '\(tunnel)' removed")
            flushDNSCache()
        }
    }

    private func add(_ key: String, _ value: [String: Any]) {
        if !SCDynamicStoreAddTemporaryValue(store, key as CFString, value as CFDictionary) {
            log("  ! could not publish \(key): \(String(cString: SCErrorString(SCError())))")
        }
    }
}

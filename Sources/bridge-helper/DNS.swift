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
                  fullTunnel: config.isFullTunnel && !config.dnsOnlyForDomains, interface: interface,
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

        lock.lock()
        defer { lock.unlock() }
        removeLocked(tunnel: tunnel, flush: false)

        if !settings.fullTunnel && settings.searchDomains.isEmpty {
            // Split tunnel whose server sent DNS but no domains: like Shimo and Tunnelblick,
            // make the VPN's DNS the system resolver without touching routes.
            return overridePrimaryLocked(tunnel: tunnel, servers: settings.servers)
        }

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
        if override?.tunnel == tunnel { restoreOverrideLocked() }
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

    // MARK: System-wide DNS for split tunnels

    /// The primary service's DNS as it was before Bridge changed it.
    private struct Override: Codable {
        var tunnel: String
        var serviceID: String
        var servers: [String]
        var originalState: Data?
        var originalSetup: Data?
    }

    private var override: Override?
    private var watchdog: DispatchSourceTimer?
    private static let overridePath = "/var/run/bridge/dns-override.plist"

    private func primaryServiceID() -> String? {
        (SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any])?["PrimaryService"]
            as? String
    }

    private func keys(_ service: String) -> (state: String, setup: String) {
        ("State:/Network/Service/\(service)/DNS", "Setup:/Network/Service/\(service)/DNS")
    }

    private static func encode(_ value: CFPropertyList?) -> Data? {
        value.flatMap { try? PropertyListSerialization.data(fromPropertyList: $0, format: .binary, options: 0) }
    }

    private static func decode(_ data: Data?) -> CFPropertyList? {
        data.flatMap { try? PropertyListSerialization.propertyList(from: $0, options: [], format: nil) as CFPropertyList }
    }

    private func overridePrimaryLocked(tunnel: String, servers: [String]) -> String? {
        if let current = override, current.tunnel != tunnel {
            return "DNS is already provided by '\(current.tunnel)'; keeping it."
        }
        guard let service = primaryServiceID() else { return "No primary network service; DNS left unchanged." }
        let (stateKey, setupKey) = keys(service)
        if override == nil {
            override = Override(tunnel: tunnel, serviceID: service, servers: servers,
                                originalState: Self.encode(SCDynamicStoreCopyValue(store, stateKey as CFString)),
                                originalSetup: Self.encode(SCDynamicStoreCopyValue(store, setupKey as CFString)))
            persistOverride()
        }
        for key in [stateKey, setupKey] {
            var dns = (SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any]) ?? [:]
            dns["ServerAddresses"] = servers
            SCDynamicStoreSetValue(store, key as CFString, dns as CFDictionary)
        }
        active[tunnel] = servers
        log("  DNS \(servers.joined(separator: ", ")) for all names (no domains from the server; service \(service))")
        flushDNSCache()
        startWatchdog()
        return nil
    }

    private func restoreOverrideLocked() {
        guard let saved = override else { return }
        let (stateKey, setupKey) = keys(saved.serviceID)
        for (key, original) in [(stateKey, saved.originalState), (setupKey, saved.originalSetup)] {
            if let value = Self.decode(original) {
                SCDynamicStoreSetValue(store, key as CFString, value)
            } else {
                SCDynamicStoreRemoveValue(store, key as CFString)
            }
        }
        override = nil
        active[saved.tunnel] = nil
        try? FileManager.default.removeItem(atPath: Self.overridePath)
        watchdog?.cancel()
        watchdog = nil
        log("  system DNS restored (service \(saved.serviceID))")
        flushDNSCache()
    }

    private func persistOverride() {
        guard let override, let data = try? PropertyListEncoder().encode(override) else { return }
        try? data.write(to: URL(fileURLWithPath: Self.overridePath), options: .atomic)
    }

    /// DHCP renewals or another VPN may rewrite the primary service's DNS, and the
    /// primary service itself may change: keep the override in place.
    private func startWatchdog() {
        guard watchdog == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
        timer.schedule(deadline: .now() + 15, repeating: 15)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.lock.lock()
            defer { self.lock.unlock() }
            guard let saved = self.override else { return }
            let service = self.primaryServiceID()
            if service != saved.serviceID {
                log("  primary network service changed; moving DNS override")
                let tunnel = saved.tunnel, servers = saved.servers
                self.restoreOverrideLocked()
                _ = self.overridePrimaryLocked(tunnel: tunnel, servers: servers)
                return
            }
            let current = (SCDynamicStoreCopyValue(self.store, self.keys(saved.serviceID).state as CFString)
                as? [String: Any])?["ServerAddresses"] as? [String]
            if current != saved.servers {
                log("  system DNS was changed by someone else; applying VPN DNS again")
                _ = self.overridePrimaryLocked(tunnel: saved.tunnel, servers: saved.servers)
            }
        }
        timer.resume()
        watchdog = timer
    }

    /// Restores DNS that a crashed helper left overridden.
    func recoverOverride() {
        lock.lock()
        defer { lock.unlock() }
        guard let data = FileManager.default.contents(atPath: Self.overridePath),
              let saved = try? PropertyListDecoder().decode(Override.self, from: data) else { return }
        log("restoring system DNS left over by '\(saved.tunnel)'")
        override = saved
        restoreOverrideLocked()
    }

    private func add(_ key: String, _ value: [String: Any]) {
        if !SCDynamicStoreAddTemporaryValue(store, key as CFString, value as CFDictionary) {
            log("  ! could not publish \(key): \(String(cString: SCErrorString(SCError())))")
        }
    }
}

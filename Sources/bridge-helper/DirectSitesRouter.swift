import BridgeCore
import Foundation

/// Routes the addresses of direct sites around one tunnel, through the physical uplink.
///
/// DNS for the domains and all their subdomains goes to `DirectDNSProxy`, which asks
/// the physical network's DNS through the physical interface and reports every address
/// it hands out; each gets a host route via the uplink before the app can connect.
/// The domain and its `www.` host are also looked up every few minutes, so the main
/// addresses are routed even before anything asks. Addresses stay routed for a while after
/// they drop out of the answers, as browsers keep connections and their own DNS cache.
/// Runs on the manager queue; lookups run in the background.
final class DirectSitesRouter {
    let tunnel: String
    private let queue: DispatchQueue

    /// From the tunnel's own settings (“All traffic except these networks”).
    var ownDomains: [String] = []
    /// The app's global list: applies only while the tunnel takes all traffic.
    var globalDomains: [String] = []

    var takesAllTraffic: () -> Bool = { false }
    var carriesIPv6: () -> Bool = { false }
    /// VPN servers: routed by the manager, never touched here.
    var protectedAddresses: () -> Set<String> = { [] }
    var tunnelInterfaces: () -> Set<String> = { [] }
    var onRoutesChanged: () -> Void = {}

    /// Routes this router added (and so removes).
    private(set) var routes: [RouteEntry] = []

    private struct Seen {
        var domains: Set<String>
        var lastSeen: Date
    }

    private var seen: [IPAddress: Seen] = [:]
    private var unresolved: Set<String> = []
    private var timer: DispatchSourceTimer?
    private var resolving = false
    private var again = false
    private var stopped = false

    static let refreshInterval: TimeInterval = 300
    /// How long an address stays routed after its domain stopped returning it.
    static let keepAddresses: TimeInterval = 6 * 3600
    static let maxAddresses = 2000

    init(tunnel: String, queue: DispatchQueue) {
        self.tunnel = tunnel
        self.queue = queue
    }

    var domains: [String] {
        var out = ownDomains
        if takesAllTraffic() {
            for domain in globalDomains where !out.contains(domain) { out.append(domain) }
        }
        return out
    }

    func start() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + Self.refreshInterval, repeating: Self.refreshInterval, leeway: .seconds(30))
        timer.setEventHandler { [weak self] in self?.refresh() }
        timer.resume()
        self.timer = timer
        refresh()
    }

    func stop() {
        stopped = true
        timer?.cancel()
        timer = nil
        for route in routes.reversed() { Routes.delete(route, quiet: true) }
        if !routes.isEmpty { log("  direct sites of '\(tunnel)': \(routes.count) route(s) removed") }
        routes.removeAll()
        DNSManager.shared.removeDirect(tunnel: tunnel)
    }

    /// Looks the domains up again and follows the current uplink (also after network changes).
    func refresh() {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !stopped else { return }
        if resolving {
            again = true
            return
        }
        let domains = self.domains
        forget(except: Set(domains))
        guard !domains.isEmpty else {
            DNSManager.shared.removeDirect(tunnel: tunnel)
            reconcile()
            return
        }
        guard let uplink = Routes.uplink(excluding: tunnelInterfaces()), let interface = uplink.interface,
              !Routes.isVirtual(interface) else {
            log("  direct sites of '\(tunnel)': no physical network, leaving them in the tunnel")
            DNSManager.shared.removeDirect(tunnel: tunnel)
            reconcile()
            return
        }

        // The physical network's DNS answers these domains, asked through the proxy on that interface.
        var servers = DNSManager.shared.physicalServers(interface: interface)
        if servers.isEmpty, let gateway = uplink.gateway { servers = [gateway] }
        reconcile()
        let proxy = DirectDNSProxy.shared
        let allowIPv6 = carriesIPv6() && Routes.uplinkIPv6() != nil
        let next = DirectDNSProxy.Upstream(servers: servers, interface: interface, allowIPv6: allowIPv6)
        if proxy.upstream != next {
            proxy.upstream = next
            log("  direct sites of '\(tunnel)': DNS via \(servers.joined(separator: ", ")) on \(interface)"
                + (allowIPv6 ? "" : ", IPv4 only"))
        }
        if !servers.isEmpty, proxy.start() {
            DNSManager.shared.applyDirect(tunnel: tunnel, domains: domains, servers: [DirectDNSProxy.address],
                                          port: DirectDNSProxy.port)
        } else {
            // Without the proxy the system resolver answers (through the tunnel's DNS).
            DNSManager.shared.removeDirect(tunnel: tunnel)
            log("  direct sites of '\(tunnel)': no DNS proxy; only the domains and www. hosts are routed")
        }

        resolving = true
        DispatchQueue.global(qos: .utility).async { [weak self] in
            var answers: [String: [IPAddress]] = [:]
            for domain in domains {
                var ips: [IPAddress] = []
                for host in DirectSites.hostNames(for: domain) {
                    for ip in Resolver.resolveAll(host) where !ips.contains(ip) { ips.append(ip) }
                }
                answers[domain] = Array(ips.prefix(DirectSites.maxAddressesPerDomain))
            }
            guard let self else { return }
            self.queue.async {
                self.resolving = false
                guard !self.stopped else { return }
                self.merge(answers)
                self.reconcile()
                if self.again {
                    self.again = false
                    self.refresh()
                }
            }
        }
    }

    private func merge(_ answers: [String: [IPAddress]], replacesUnresolved: Bool = true) {
        let now = Date()
        let protected = protectedAddresses()
        for (domain, ips) in answers {
            if ips.isEmpty {
                if replacesUnresolved { unresolved.insert(domain) }
            } else {
                unresolved.remove(domain)
            }
            for ip in ips where DirectSites.isRoutable(ip) && !protected.contains("\(ip)") {
                var entry = seen[ip] ?? Seen(domains: [], lastSeen: now)
                entry.domains.insert(domain)
                entry.lastSeen = now
                seen[ip] = entry
            }
        }
        // Old addresses go after a while; and never more than the cap, oldest first.
        seen = seen.filter { now.timeIntervalSince($0.value.lastSeen) < Self.keepAddresses }
        if seen.count > Self.maxAddresses {
            let keep = seen.sorted { $0.value.lastSeen > $1.value.lastSeen }.prefix(Self.maxAddresses)
            seen = Dictionary(uniqueKeysWithValues: keep.map { ($0.key, $0.value) })
        }
    }

    /// The domain in the list that `name` belongs to (itself or a subdomain).
    func domain(for name: String) -> String? {
        let name = name.lowercased()
        return domains.filter { name == $0 || name.hasSuffix("." + $0) }.max { $0.count < $1.count }
    }

    /// Addresses the DNS proxy just handed out for `name`: route them now.
    func learn(name: String, addresses: [IPAddress]) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !stopped, let domain = domain(for: name) else { return }
        let fresh = addresses.prefix(DirectSites.maxAddressesPerDomain)
        merge([domain: Array(fresh)], replacesUnresolved: false)
        reconcile()
    }

    /// Drops addresses of domains that are no longer in the list.
    private func forget(except domains: Set<String>) {
        unresolved.formIntersection(domains)
        for (ip, entry) in seen {
            let left = entry.domains.intersection(domains)
            if left.isEmpty { seen[ip] = nil } else { seen[ip]?.domains = left }
        }
    }

    /// Makes the installed routes match the wanted addresses on the current uplink.
    private func reconcile() {
        let ours = tunnelInterfaces()
        let v4 = Routes.uplink(excluding: ours).flatMap { $0.interface.map(Routes.isVirtual) == false ? $0 : nil }
        let v6 = carriesIPv6() ? Routes.uplinkIPv6() : nil

        func entry(_ ip: IPAddress) -> RouteEntry? {
            guard let path = ip.isIPv6 ? v6 : v4 else { return nil }
            return RouteEntry(destination: "\(ip)", ipv6: ip.isIPv6, gateway: path.gateway,
                              interface: path.gateway == nil ? path.interface : nil)
        }
        var wanted: [RouteEntry] = []
        let protected = protectedAddresses()
        for ip in seen.keys.sorted(by: { "\($0)" < "\($1)" }) where !protected.contains("\(ip)") {
            if let route = entry(ip) { wanted.append(route) }
        }

        let wantedSet = Set(wanted)
        var removed = 0, added = 0
        for route in routes where !wantedSet.contains(route) {
            Routes.delete(route, quiet: true)
            removed += 1
        }
        routes.removeAll { !wantedSet.contains($0) }
        var failed: [String] = []
        for route in wanted where !routes.contains(route) {
            do {
                if try Routes.add(route, quiet: true) {
                    routes.append(route)
                    added += 1
                }
            } catch {
                failed.append(route.destination)
            }
        }
        if added > 0 || removed > 0 {
            let via = v4?.interface ?? v6?.interface ?? "?"
            log("  direct sites of '\(tunnel)': \(routes.count) address(es) via \(via) (+\(added) −\(removed))")
            onRoutesChanged()
        }
        if !failed.isEmpty {
            log("  ! direct sites of '\(tunnel)': could not route \(failed.prefix(5).joined(separator: ", "))"
                + (failed.count > 5 ? " and \(failed.count - 5) more" : ""))
        }
    }

    func statuses() -> [DirectSiteStatus] {
        let routed = Set(routes.map(\.destination))
        return domains.map { domain in
            let ips = seen.filter { $0.value.domains.contains(domain) }.map(\.key)
            let through = ips.filter { $0.isIPv6 && !routed.contains("\($0)") }.count
            return DirectSiteStatus(domain: domain, addresses: ips.filter { routed.contains("\($0)") }.count,
                                    unresolved: unresolved.contains(domain),
                                    ipv6ThroughTunnel: carriesIPv6() ? through : 0)
        }
    }
}

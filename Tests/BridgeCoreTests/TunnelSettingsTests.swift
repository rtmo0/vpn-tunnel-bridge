import Foundation
import Testing
@testable import BridgeCore

private func key(_ seed: UInt8) -> String { Data((0..<32).map { UInt8($0) &+ seed }).base64EncodedString() }

private let wg = """
[Interface]
PrivateKey = \(key(1))
Address = 10.9.9.6/32
DNS = 1.1.1.1
[Peer]
PublicKey = \(key(2))
Endpoint = 203.0.113.7:51820
AllowedIPs = 0.0.0.0/0, ::/0
"""

@Suite struct TunnelSettingsTests {
    @Test func defaultsChangeNothing() throws {
        let config = try TunnelConfig.parse(wg)
        let (out, bypass) = try config.applying(TunnelSettings())
        #expect(out == config)
        #expect(bypass.isEmpty)
    }

    @Test func splitTunnelOnlyListed() throws {
        var s = TunnelSettings()
        s.routing = .onlyListed
        s.networks = ["10.0.0.0/8", "192.168.50.1"]
        let (out, bypass) = try TunnelConfig.parse(wg).applying(s)
        #expect(out.peers[0].allowedIPs.map(\.description) == ["10.0.0.0/8", "192.168.50.1/32"])
        #expect(!out.isFullTunnel)
        #expect(bypass.isEmpty)
    }

    @Test func allExceptListedAndLocalNetworks() throws {
        var s = TunnelSettings()
        s.routing = .allExceptListed
        s.networks = ["198.51.100.0/24"]
        s.excludeLocalNetworks = true
        let (out, bypass) = try TunnelConfig.parse(wg).applying(s)
        #expect(out.isFullTunnel)
        #expect(bypass.map(\.description).contains("198.51.100.0/24"))
        #expect(bypass.map(\.description).contains("192.168.0.0/16"))
    }

    @Test func customAndSplitDNS() throws {
        var s = TunnelSettings()
        s.dnsMode = .custom
        s.dnsServers = ["9.9.9.9"]
        s.splitDNSDomains = ["corp.example"]
        let (out, _) = try TunnelConfig.parse(wg).applying(s)
        #expect(out.dnsServers.map(\.description) == ["9.9.9.9"])
        #expect(out.dnsSearchDomains == ["corp.example"])
        #expect(out.dnsOnlyForDomains)

        s = TunnelSettings()
        s.dnsMode = .system
        #expect(try TunnelConfig.parse(wg).applying(s).config.dnsServers.isEmpty)
    }

    @Test func validation() {
        var s = TunnelSettings()
        s.routing = .onlyListed
        #expect(throws: ConfigError.self) { try s.validate() }
        s.networks = ["not-a-network"]
        #expect(throws: ConfigError.self) { try s.validate() }
        s = TunnelSettings()
        s.dnsMode = .custom
        s.dnsServers = ["dns.example"]
        #expect(throws: ConfigError.self) { try s.validate() }
    }

    @Test func openVPNDirectives() throws {
        let base = try OpenVPNConfig.parse("client\nremote vpn.example 1194\n")
        var s = TunnelSettings()
        s.routing = .onlyListed
        s.networks = ["10.20.0.0/16"]
        s.dnsMode = .custom
        s.dnsServers = ["10.20.0.53"]
        s.splitDNSDomains = ["corp.example"]
        let text = try base.applying(s).render()
        #expect(text.contains("pull-filter ignore redirect-gateway"))
        #expect(text.contains(#"pull-filter ignore "route ""#))
        #expect(text.contains("route 10.20.0.0 255.255.0.0"))
        #expect(text.contains(#"pull-filter ignore "dhcp-option DNS""#))
        #expect(text.contains("dhcp-option DNS 10.20.0.53"))
        #expect(text.contains("dhcp-option DOMAIN corp.example"))
        #expect(text.contains("setenv BRIDGE_DNS_SPLIT 1"))

        var e = TunnelSettings()
        e.routing = .allExceptListed
        e.networks = ["192.0.2.0/24"]
        let excluded = try base.applying(e).render()
        #expect(excluded.contains("redirect-gateway def1"))
        #expect(excluded.contains("route 192.0.2.0 255.255.255.0 net_gateway"))
    }
}

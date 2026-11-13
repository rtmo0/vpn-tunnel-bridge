import Foundation
import Testing
@testable import BridgeCore

/// The vpnc-script environment ocserv 1.3 produced for a split-tunnel group.
private let splitEnvironment: [String: String] = [
    "reason": "connect", "TUNDEV": "utun7", "VPNGATEWAY": "192.168.0.10", "VPNPID": "4242",
    "CISCO_BANNER": "Bridge test server", "CISCO_DEF_DOMAIN": "bridge.test", "CISCO_SPLIT_DNS": "corp.bridge.test",
    "INTERNAL_IP4_ADDRESS": "192.168.99.50", "INTERNAL_IP4_DNS": "1.1.1.1", "INTERNAL_IP4_MTU": "1340",
    "INTERNAL_IP4_NETADDR": "192.168.99.0", "INTERNAL_IP4_NETMASK": "255.255.255.0", "INTERNAL_IP4_NETMASKLEN": "24",
    "CISCO_SPLIT_INC": "1", "CISCO_SPLIT_INC_0_ADDR": "1.0.0.0", "CISCO_SPLIT_INC_0_MASK": "255.255.255.0",
    "CISCO_SPLIT_INC_0_MASKLEN": "24",
    "CISCO_SPLIT_EXC": "1", "CISCO_SPLIT_EXC_0_ADDR": "192.168.0.0", "CISCO_SPLIT_EXC_0_MASK": "255.255.0.0",
    "CISCO_SPLIT_EXC_0_MASKLEN": "16",
]

@Suite struct OpenConnectTests {
    @Test func parsesProfile() throws {
        let text = """
        # Bridge OpenConnect profile
        Protocol = gp
        Server = vpn.example.com/gateway
        Username = alice
        Group = Employees
        ServerCert = pin-sha256:iI7F+0tUIsiXgO7+IcRgn7AtP1voZPPR2s/oFvzrA7s=
        ReportedOS = win
        NoDTLS = yes

        [Certificate]
        -----BEGIN CERTIFICATE-----
        MIIBszCCAVmgAwIBAgIU
        Zw==
        -----END CERTIFICATE-----
        """
        #expect(TunnelKind.detect(text) == .openconnect)
        let c = try OpenConnectConfig.parse(text)
        #expect(c.vpnProtocol == .gp)
        #expect(c.url == "https://vpn.example.com/gateway")
        #expect(c.host == "vpn.example.com")
        #expect(c.username == "alice")
        #expect(c.group == "Employees")
        #expect(c.reportedOS == "win")
        #expect(c.disableDTLS)
        // A base64 line ending in "=" stays inside the PEM block.
        #expect(c.certificate?.contains("Zw==\n-----END CERTIFICATE-----") == true)
        #expect(try OpenConnectConfig.parse(c.render()) == c)
    }

    @Test(arguments: [
        ("Protocol = anyconnect", "no “Server"),
        ("Server = vpn.example.com\nProtocol = ipsec", "Unknown protocol"),
        ("Server = vpn.example.com\nPassword = secret", "Unknown key"),
        ("Server = vpn.example.com\nServer = other", "appears twice"),
        ("Server = vpn.example.com\nReportedOS = beos", "ReportedOS"),
        ("Server = vpn.example.com\n[Key]\nabc", "needs a [Certificate]"),
        ("Server = http://vpn.example.com", "not a server address"),
    ])
    func rejects(text: String, message: String) {
        #expect {
            try OpenConnectConfig.parse(text)
        } throws: { error in
            "\(error)".contains(message)
        }
    }

    @Test func readsServerAssignedNetwork() throws {
        let n = try #require(OpenConnectNetwork(environment: splitEnvironment))
        #expect(n.interface == "utun7")
        #expect(n.gateway == "192.168.0.10")
        #expect(n.ipv4 == "192.168.99.50")
        #expect(n.ipv4Network?.description == "192.168.99.0/24")
        #expect(n.mtu == 1340)
        #expect(n.dnsServers.map(\.description) == ["1.1.1.1"])
        #expect(n.splitDNS == ["corp.bridge.test"])
        #expect(n.includes.map(\.description) == ["1.0.0.0/24"])
        #expect(n.excludes.map(\.description) == ["192.168.0.0/16"])
        // Anything that isn't a plain interface name is refused.
        var bad = splitEnvironment
        bad["TUNDEV"] = "utun7; rm -rf /"
        #expect(OpenConnectNetwork(environment: bad) == nil)
    }

    @Test func plansSplitTunnelAndSplitDNS() throws {
        let plan = try #require(OpenConnectNetwork(environment: splitEnvironment)).plan(TunnelSettings())
        #expect(!plan.isFullTunnel)
        #expect(plan.networks.map(\.description) == ["1.0.0.0/24"])
        #expect(plan.bypass.map(\.description) == ["192.168.0.0/16"])
        #expect(plan.searchDomains == ["corp.bridge.test"])
        #expect(plan.dnsOnlyForDomains)
    }

    @Test func fullTunnelWithoutSplitIncludes() throws {
        var env = splitEnvironment
        for key in env.keys where key.hasPrefix("CISCO_SPLIT") { env[key] = nil }
        let plan = try #require(OpenConnectNetwork(environment: env)).plan(TunnelSettings())
        #expect(plan.isFullTunnel)
        #expect(plan.searchDomains == ["bridge.test"])
        #expect(!plan.dnsOnlyForDomains)
    }

    @Test func settingsOverrideServerRoutes() throws {
        var settings = TunnelSettings()
        settings.routing = .onlyListed
        settings.networks = ["10.20.0.0/16"]
        settings.dnsMode = .custom
        settings.dnsServers = ["9.9.9.9"]
        settings.splitDNSDomains = ["internal.example"]
        let plan = try #require(OpenConnectNetwork(environment: splitEnvironment)).plan(settings)
        #expect(plan.networks.map(\.description) == ["10.20.0.0/16"])
        #expect(plan.bypass.isEmpty)  // the user chose the routes; server exclusions don't apply
        #expect(plan.dnsServers.map(\.description) == ["9.9.9.9"])
        #expect(plan.searchDomains == ["internal.example"])
        #expect(plan.dnsOnlyForDomains)
    }
}

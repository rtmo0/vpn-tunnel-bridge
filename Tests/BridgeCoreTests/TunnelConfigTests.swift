import Foundation
import Testing
@testable import BridgeCore

/// Deterministic fake 32-byte keys (not real secrets).
private func fakeKey(_ seed: UInt8) -> String {
    Data((0..<32).map { UInt8(truncatingIfNeeded: Int($0) &* 7 &+ Int(seed)) }).base64EncodedString()
}

private let amneziaV2Config = """
[Interface]
PrivateKey = \(fakeKey(1))
Address = 10.9.9.6/32, fd00::6/128
DNS = 1.1.1.1, 1.0.0.1, corp.example
MTU = 1280
Jc = 3
Jmin = 49
Jmax = 244
S1 = 27
S2 = 94
S3 = 45
S4 = 18
H1 = 1
H2 = 2
H3 = 3
H4 = 100-200
I1 = <r 2><b 0x8580000100020000000037><rc 55>
HeaderProtectionKey = \(fakeKey(2))
ContentPaddingAddition = 32-128
PostUp = rm -rf /   # must never run

[Peer]
PublicKey = \(fakeKey(3))
PresharedKey = \(fakeKey(4))
Endpoint = vpn.example.com:39743
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 33
"""

@Suite struct TunnelConfigTests {
    @Test func parsesEveryAmneziaParameter() throws {
        let config = try TunnelConfig.parse(amneziaV2Config)
        let names = config.deviceParameters.map(\.name)
        #expect(names == ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
                          "I1", "HeaderProtectionKey", "ContentPaddingAddition"])
        #expect(config.parameter("I1")?.value == "<r 2><b 0x8580000100020000000037><rc 55>")
        #expect(config.parameter("H4")?.value == "100-200")
        #expect(config.usesAmneziaObfuscation)
        #expect(config.isFullTunnel)
        #expect(config.mtu == 1280)
        #expect(config.addresses.map(\.description) == ["10.9.9.6/32", "fd00::6/128"])
        #expect(config.dnsServers.map(\.description) == ["1.1.1.1", "1.0.0.1"])
        #expect(config.dnsSearchDomains == ["corp.example"])
        #expect(config.peers.count == 1)
        #expect(config.peers[0].endpoint?.host == "vpn.example.com")
        #expect(config.peers[0].endpoint?.port == 39743)
        #expect(config.warnings.contains { $0.hasPrefix("PostUp is ignored") })
    }

    @Test func keysAreCaseInsensitive() throws {
        let text = amneziaV2Config.replacingOccurrences(of: "HeaderProtectionKey", with: "headerprotectionkey")
        let config = try TunnelConfig.parse(text)
        #expect(config.parameter("HeaderProtectionKey") != nil)
    }

    @Test func rejectsUnknownInterfaceKeyInsteadOfDroppingIt() {
        let text = amneziaV2Config.replacingOccurrences(of: "Jc = 3", with: "Jc = 3\nFutureParam = 7")
        #expect(throws: ConfigError.self) { try TunnelConfig.parse(text) }
    }

    @Test func rejectsBadKeys() {
        let text = amneziaV2Config.replacingOccurrences(of: "HeaderProtectionKey = \(fakeKey(2))",
                                                        with: "HeaderProtectionKey = not-a-key")
        #expect(throws: ConfigError.self) { try TunnelConfig.parse(text) }
    }

    @Test func requiresEssentials() {
        #expect(throws: ConfigError.self) { try TunnelConfig.parse("[Peer]\nPublicKey = \(fakeKey(3))") }
        #expect(throws: ConfigError.self) {
            try TunnelConfig.parse("[Interface]\nPrivateKey = \(fakeKey(1))\nAddress = 10.0.0.2/32")
        }
    }

    @Test func plainWireGuardIsNotAmnezia() throws {
        let text = """
        [Interface]
        PrivateKey = \(fakeKey(1))
        Address = 10.0.0.2/24
        [Peer]
        PublicKey = \(fakeKey(3))
        Endpoint = [2001:db8::1]:51820
        AllowedIPs = 10.0.0.0/24
        """
        let config = try TunnelConfig.parse(text)
        #expect(!config.usesAmneziaObfuscation)
        #expect(!config.isFullTunnel)
        #expect(config.peers[0].endpoint?.host == "2001:db8::1")
        #expect(config.peers[0].endpoint?.description == "[2001:db8::1]:51820")
    }
}

@Suite struct UAPITests {
    @Test func setRequestCarriesAllParameters() throws {
        let config = try TunnelConfig.parse(amneziaV2Config)
        let peerKey = config.peers[0].publicKey
        let request = try UAPI.setRequest(for: config, endpoints: [peerKey: "203.0.113.7:39743"])
        let lines = request.components(separatedBy: "\n")

        #expect(lines.first == "set=1")
        #expect(request.hasSuffix("\n\n"))
        #expect(lines.contains("private_key=\(WireGuardKey.hex(fromBase64: fakeKey(1))!)"))
        for expected in ["jc=3", "jmin=49", "jmax=244", "s1=27", "s2=94", "s3=45", "s4=18",
                         "h1=1", "h2=2", "h3=3", "h4=100-200",
                         "i1=<r 2><b 0x8580000100020000000037><rc 55>",
                         "content_padding_addition=32-128",
                         "header_protection_key=\(WireGuardKey.hex(fromBase64: fakeKey(2))!)",
                         "replace_peers=true",
                         "public_key=\(WireGuardKey.hex(fromBase64: fakeKey(3))!)",
                         "preshared_key=\(WireGuardKey.hex(fromBase64: fakeKey(4))!)",
                         "endpoint=203.0.113.7:39743",
                         "persistent_keepalive_interval=33",
                         "replace_allowed_ips=true",
                         "allowed_ip=0.0.0.0/0", "allowed_ip=::/0"] {
            #expect(lines.contains(expected), "missing \(expected)")
        }
        // Device keys must come before the first peer.
        let firstPeer = try #require(lines.firstIndex { $0.hasPrefix("public_key=") })
        let s3 = try #require(lines.firstIndex(of: "s3=45"))
        #expect(s3 < firstPeer)
    }

    @Test func parsesGetResponse() throws {
        let hex = WireGuardKey.hex(fromBase64: fakeKey(3))!
        let response = """
        private_key=00
        listen_port=53895
        jc=3
        public_key=\(hex)
        protocol_version=1
        endpoint=203.0.113.7:39743
        last_handshake_time_sec=1700000000
        last_handshake_time_nsec=500000000
        tx_bytes=1824
        rx_bytes=96
        persistent_keepalive_interval=33
        allowed_ip=0.0.0.0/0
        errno=0


        """
        let status = try UAPI.parseGetResponse(response)
        #expect(status.listenPort == 53895)
        #expect(status.peers.count == 1)
        #expect(status.peers[0].publicKey == fakeKey(3))
        #expect(status.peers[0].rxBytes == 96)
        #expect(status.peers[0].txBytes == 1824)
        #expect(status.peers[0].lastHandshake == Date(timeIntervalSince1970: 1_700_000_000.5))
    }

    @Test func reportsBackendErrors() {
        #expect(throws: UAPI.ProtocolError.self) { try UAPI.parseGetResponse("errno=22\n\n") }
    }
}

@Suite struct IPNetworkTests {
    @Test func containment() throws {
        let any4 = try #require(IPNetwork("0.0.0.0/0"))
        let net = try #require(IPNetwork("10.9.0.0/16"))
        let ip = try #require(IPAddress("10.9.9.6"))
        #expect(any4.contains(ip))
        #expect(net.contains(ip))
        #expect(!net.contains(try #require(IPAddress("10.10.0.1"))))
        #expect(!any4.contains(try #require(IPAddress("::1"))))
        #expect(try #require(IPNetwork("fd00::/8")).contains(try #require(IPAddress("fd12::1"))))
    }

    @Test func masking() throws {
        #expect(try #require(IPNetwork("10.9.9.6/24")).masked.description == "10.9.9.0/24")
        #expect(try #require(IPNetwork("fd00::6/64")).masked.description == "fd00::/64")
        #expect(try #require(IPNetwork("1.2.3.4")).description == "1.2.3.4/32")
    }

    @Test func tunnelNames() {
        #expect(TunnelName.isValid("nl2-internet"))
        #expect(!TunnelName.isValid("../etc"))
        #expect(!TunnelName.isValid("имя"))
        #expect(!TunnelName.isValid(""))
    }
}

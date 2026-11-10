import Foundation
import Testing
@testable import BridgeCore

private let providerConfig = """
client
dev tun
proto udp
remote vpn.example.com 1194
remote 203.0.113.9 443 tcp   # fallback
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
static-challenge "Enter OTP" 1
redirect-gateway def1
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
block-outside-dns
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIBfake
-----END CERTIFICATE-----
</ca>
key-direction 1
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
abcd
-----END OpenVPN Static key V1-----
</tls-auth>
"""

@Suite struct OpenVPNConfigTests {
    @Test func parsesDirectivesAndInlineBlocks() throws {
        let config = try OpenVPNConfig.parse(providerConfig)
        #expect(config.remotes == ["vpn.example.com:1194", "203.0.113.9:443"])
        #expect(config.needsUsernamePassword)
        #expect(config.staticChallenge?.text == "Enter OTP")
        #expect(config.staticChallenge?.echo == true)
        #expect(config.redirectsGateway)
        #expect(config.first("ca")?.inline?.contains("MIIBfake") == true)
        #expect(config.first("tls-auth")?.inline?.contains("abcd") == true)
    }

    @Test func tokenizerHandlesQuotesAndComments() throws {
        #expect(try OpenVPNConfig.tokenize(#"static-challenge "Enter your code" 1"#, line: 1)
            == ["static-challenge", "Enter your code", "1"])
        #expect(try OpenVPNConfig.tokenize("remote a.example 1194 # comment", line: 1) == ["remote", "a.example", "1194"])
        #expect(try OpenVPNConfig.tokenize(#"setenv X "a \"b\" c""#, line: 1) == ["setenv", "X", #"a "b" c"#])
        #expect(try OpenVPNConfig.tokenize("verb 3;x", line: 1) == ["verb", "3;x"])
        #expect(throws: ConfigError.self) { try OpenVPNConfig.tokenize(#"x "open"#, line: 1) }
    }

    @Test func preparedConfigStripsScriptsAndAddsBridgeHooks() throws {
        let config = try OpenVPNConfig.parse(providerConfig)
        let prepared = try config.prepared(tunnel: "work", managementSocket: "/var/run/bridge/work.mgmt",
                                           eventCommand: "/opt/helper openvpn-event")
        let lines = prepared.text.components(separatedBy: "\n")
        #expect(!lines.contains { $0.hasPrefix("up /etc") })
        #expect(!lines.contains { $0.hasPrefix("down /etc") })
        #expect(!lines.contains("block-outside-dns"))
        #expect(!lines.contains("dev tun"))
        #expect(lines.contains("dev utun"))
        #expect(lines.contains("management /var/run/bridge/work.mgmt unix"))
        #expect(lines.contains("management-query-passwords"))
        #expect(lines.contains(#"route-up "/opt/helper openvpn-event up""#))
        #expect(lines.contains(#"down "/opt/helper openvpn-event down""#))
        #expect(lines.contains("setenv BRIDGE_TUNNEL work"))
        #expect(lines.contains("<ca>"))
        #expect(prepared.warnings.contains { $0.contains("never runs scripts") })
        #expect(prepared.warnings.contains { $0.contains("Windows-only") })
        // Re-parsing the prepared text must work.
        #expect(try OpenVPNConfig.parse(prepared.text).has("management-hold"))
    }

    @Test func rejectsUnsafeOrUnsupported() throws {
        let withFile = try OpenVPNConfig.parse("client\nremote a 1194\nca /etc/ssl/ca.pem\n")
        #expect(throws: ConfigError.self) {
            try withFile.prepared(tunnel: "t", managementSocket: "/m", eventCommand: "/e")
        }
        let tap = try OpenVPNConfig.parse("client\nremote a 1194\ndev tap0\n")
        #expect(throws: ConfigError.self) { try tap.prepared(tunnel: "t", managementSocket: "/m", eventCommand: "/e") }
        let include = try OpenVPNConfig.parse("client\nremote a 1194\nconfig /etc/other.conf\n")
        #expect(throws: ConfigError.self) {
            try include.prepared(tunnel: "t", managementSocket: "/m", eventCommand: "/e")
        }
        #expect(throws: ConfigError.self) { try OpenVPNConfig.parse("client\ndev tun\n") }
    }

    @Test func inliningReadsReferencedFiles() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try "CA-DATA\n".write(to: dir.appendingPathComponent("ca.crt"), atomically: true, encoding: .utf8)
        try "TA-DATA\n".write(to: dir.appendingPathComponent("ta.key"), atomically: true, encoding: .utf8)
        try "alice\nsecret\n".write(to: dir.appendingPathComponent("creds.txt"), atomically: true, encoding: .utf8)

        let config = try OpenVPNConfig.parse("""
        client
        remote a 1194
        ca ca.crt
        tls-auth ta.key 1
        auth-user-pass creds.txt
        """)
        let (inlined, secrets) = try config.inliningFiles(relativeTo: dir)
        #expect(inlined.first("ca")?.inline == "CA-DATA")
        #expect(inlined.first("tls-auth")?.inline == "TA-DATA")
        #expect(inlined.first("key-direction")?.args == ["1"])
        #expect(inlined.first("auth-user-pass")?.args == [])
        #expect(secrets.username == "alice")
        #expect(secrets.password == "secret")
        _ = try inlined.prepared(tunnel: "t", managementSocket: "/m", eventCommand: "/e")
    }

    @Test func detectsKind() {
        #expect(TunnelKind.detect(providerConfig) == .openvpn)
        #expect(TunnelKind.detect("[Interface]\nPrivateKey = x\n") == .amneziawg)
    }

    @Test func sanitizesNames() {
        #expect(TunnelName.sanitized("My Server (NL)") == "My-Server-NL")
        #expect(TunnelName.sanitized("сервер") == "tunnel")
        #expect(TunnelName.isValid(TunnelName.sanitized("a b.c_d")))
    }
}

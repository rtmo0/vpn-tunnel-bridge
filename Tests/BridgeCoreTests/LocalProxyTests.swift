import Foundation
import Testing
@testable import BridgeCore

@Suite struct LocalProxyTests {
    @Test func settingsRoundTripAndValidate() throws {
        var settings = TunnelSettings()
        #expect(!settings.isLocalProxy)
        settings.proxyPort = 10808
        let decoded = try JSONDecoder().decode(TunnelSettings.self, from: JSONEncoder().encode(settings))
        #expect(decoded.proxyPort == 10808)
        #expect(decoded.isLocalProxy)
        // Older saved settings have no proxyPort.
        #expect(try JSONDecoder().decode(TunnelSettings.self, from: Data("{}".utf8)).proxyPort == nil)
        settings.proxyPort = 80
        #expect(throws: ConfigError.self) { try settings.validate() }
    }

    @Test func localProxyConfiguration() throws {
        let link = try ProxyLink.parse("vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443"
            + "?security=tls&sni=vpn.example.com&type=tcp#Test")
        let data = try link.xrayLocalProxyConfiguration(port: 10808, probePort: 40000)
        let root = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let inbounds = try #require(root["inbounds"] as? [[String: Any]])
        #expect(!inbounds.contains { $0["protocol"] as? String == "tun" })
        let local = try #require(inbounds.first { $0["tag"] as? String == "local" })
        #expect(local["protocol"] as? String == "socks")
        #expect(local["listen"] as? String == "127.0.0.1")
        #expect(local["port"] as? Int == 10808)
        // The server is resolved by Xray itself (no tunnel to loop through).
        #expect(String(decoding: data, as: UTF8.self).contains("vpn.example.com"))
    }
}

import Foundation
import Testing
@testable import BridgeCore

private let uuid = "93bde276-c344-44b9-89bc-76eadec60736"
private let pbk = "a0Q1kPTUwrs-ijmXBlQbdYwmWDBCVKTmRGx6lCtqM3o"
private let reality = "vless://\(uuid)@203.0.113.7:443?type=tcp&security=reality&pbk=\(pbk)"
    + "&fp=chrome&sni=www.microsoft.com&sid=a1b2c3d4&spx=%2F&flow=xtls-rprx-vision#NL%20Reality"

private func json(_ config: VLESSConfig) throws -> [String: Any] {
    let data = try config.xrayConfiguration(address: "203.0.113.7", interface: "utun12",
                                            gateway: "198.18.0.49/30", mtu: 1500, probePorts: (41000, 41001))
    return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
}

private func outbound(_ root: [String: Any]) throws -> [String: Any] {
    try #require((root["outbounds"] as? [[String: Any]])?.first)
}

@Suite struct VLESSConfigTests {
    @Test func parsesRealityVision() throws {
        let c = try VLESSConfig.parse(reality)
        #expect(c.id == uuid)
        #expect(c.host == "203.0.113.7")
        #expect(c.port == 443)
        #expect(c.remark == "NL Reality")
        #expect(c.transport == .raw)
        #expect(c.security == .reality)
        #expect(c.flow == "xtls-rprx-vision")
        #expect(c.serverName == "www.microsoft.com")
        #expect(c.realityShortID == "a1b2c3d4")
        #expect(c.realitySpiderX == "/")
        #expect(TunnelKind.detect("  \(reality)\n") == .vless)
    }

    @Test func rendersRealityForXray() throws {
        let root = try json(try VLESSConfig.parse(reality))
        let out = try outbound(root)
        #expect(out["protocol"] as? String == "vless")
        let vnext = try #require(((out["settings"] as? [String: Any])?["vnext"] as? [[String: Any]])?.first)
        #expect(vnext["address"] as? String == "203.0.113.7")
        #expect(vnext["port"] as? Int == 443)
        let user = try #require((vnext["users"] as? [[String: Any]])?.first)
        #expect(user["id"] as? String == uuid)
        #expect(user["flow"] as? String == "xtls-rprx-vision")
        #expect(user["encryption"] as? String == "none")
        let stream = try #require(out["streamSettings"] as? [String: Any])
        #expect(stream["network"] as? String == "raw")
        let r = try #require(stream["realitySettings"] as? [String: Any])
        #expect(r["password"] as? String == pbk)
        #expect(r["serverName"] as? String == "www.microsoft.com")
        #expect(r["shortId"] as? String == "a1b2c3d4")
        #expect(r["fingerprint"] as? String == "chrome")

        let inbounds = try #require(root["inbounds"] as? [[String: Any]])
        let tun = try #require(inbounds.first { $0["protocol"] as? String == "tun" })
        let settings = try #require(tun["settings"] as? [String: Any])
        #expect(settings["name"] as? String == "utun12")
        #expect(settings["gateway"] as? [String] == ["198.18.0.49/30"])
        let probes = inbounds.filter { $0["protocol"] as? String == "dokodemo-door" }
        #expect(probes.count == 2)
        #expect(probes.allSatisfy { $0["listen"] as? String == "127.0.0.1" })
    }

    @Test func wsWithTLSUsesTheDomainAfterResolving() throws {
        // Xray gets the resolved IP, so SNI and Host must still name the server.
        let c = try VLESSConfig.parse("vless://\(uuid)@vpn.example.com:8443?type=ws&security=tls&path=%2Fws&host=&fp=")
        let stream = try #require(try outbound(try json(c))["streamSettings"] as? [String: Any])
        #expect((stream["tlsSettings"] as? [String: Any])?["serverName"] as? String == "vpn.example.com")
        let ws = try #require(stream["wsSettings"] as? [String: Any])
        #expect(ws["path"] as? String == "/ws")
        #expect(ws["host"] as? String == "vpn.example.com")
    }

    @Test func xhttpGRPCAndHTTPUpgrade() throws {
        let xhttp = try VLESSConfig.parse("vless://\(uuid)@203.0.113.7:443?type=xhttp&security=reality&pbk=\(pbk)"
            + "&sni=www.microsoft.com&path=%2Fxh&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D")
        let xs = try #require(try outbound(try json(xhttp))["streamSettings"] as? [String: Any])
        let settings = try #require(xs["xhttpSettings"] as? [String: Any])
        #expect(settings["mode"] as? String == "packet-up")
        #expect((settings["extra"] as? [String: Any])?["xPaddingBytes"] as? String == "100-1000")

        let grpc = try VLESSConfig.parse("vless://\(uuid)@203.0.113.7:443?type=grpc&security=reality&pbk=\(pbk)"
            + "&serviceName=svc&mode=multi")
        let gs = try #require(try outbound(try json(grpc))["streamSettings"] as? [String: Any])
        #expect((gs["grpcSettings"] as? [String: Any])?["serviceName"] as? String == "svc")
        #expect((gs["grpcSettings"] as? [String: Any])?["multiMode"] as? Bool == true)

        let hu = try VLESSConfig.parse("vless://\(uuid)@[2001:db8::1]:80?type=httpupgrade&path=%2Fhu&encryption=none")
        #expect(hu.host == "2001:db8::1")
        #expect(hu.endpoint == "[2001:db8::1]:80")
        let hs = try #require(try outbound(try json(hu))["streamSettings"] as? [String: Any])
        #expect(hs["security"] as? String == "none")
        #expect((hs["httpupgradeSettings"] as? [String: Any])?["host"] == nil)
    }

    @Test(arguments: [
        ("vless://\(uuid)@h:443?type=kcp", "not supported"),
        ("vless://\(uuid)@h:443?foo=1", "Unknown parameter “foo”"),
        ("vless://\(uuid)@h:443?security=reality", "pbk"),
        ("vless://\(uuid)@h:443?security=tls&allowInsecure=1", "certificate checks"),
        ("vless://\(uuid)@h:443?type=ws&flow=xtls-rprx-vision&security=tls", "flow"),
        ("vless://\(uuid)@h:443?sni=x", "needs security"),
        ("vless://\(uuid)@h:443?type=grpc&mode=stream-up", "not valid for grpc"),
        ("vless://\(uuid)@h:443?type=xhttp&extra=nope", "JSON object"),
        ("vless://\(uuid)@h", "port"),
        ("vless://h:443", "user ID"),
        ("vless://\(uuid)@h:443?type=ws&type=grpc", "twice"),
        ("vless://\(uuid)@h:443?security=tls&pcs=abc", "SHA-256"),
    ])
    func rejects(link: String, message: String) {
        #expect {
            try VLESSConfig.parse(link)
        } throws: { error in
            "\(error)".contains(message)
        }
    }

    @Test func allowsHarmlessPanelExtras() throws {
        let c = try VLESSConfig.parse(reality + "&allowInsecure=0&headerType=none&packetEncoding=xudp")
        #expect(c.security == .reality)
    }

    @Test func routingDefaultsToEverythingWithDefaultDNS() throws {
        let routing = try VLESSConfig.parse(reality).routing(TunnelSettings())
        #expect(routing.isFullTunnel)
        #expect(routing.ipv4Networks.map(\.description) == ["0.0.0.0/0"])
        #expect(routing.ipv6Networks.map(\.description) == ["::/0"])
        #expect(routing.dnsServers.map(\.description) == VLESSConfig.defaultDNS)
    }

    @Test func routingHonoursSettings() throws {
        var s = TunnelSettings()
        s.routing = .onlyListed
        s.networks = ["10.0.0.0/8"]
        s.dnsMode = .custom
        s.dnsServers = ["9.9.9.9"]
        let routing = try VLESSConfig.parse(reality).routing(s)
        #expect(!routing.isFullTunnel)
        #expect(routing.networks.map(\.description) == ["10.0.0.0/8"])
        #expect(routing.dnsServers.map(\.description) == ["9.9.9.9"])

        var local = TunnelSettings()
        local.excludeLocalNetworks = true
        let bypass = try VLESSConfig.parse(reality).routing(local).bypass.map(\.description)
        #expect(bypass.contains("192.168.0.0/16"))
    }
}

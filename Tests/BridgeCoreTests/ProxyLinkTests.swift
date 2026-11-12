import Foundation
import Testing
@testable import BridgeCore

private let uuid = "93bde276-c344-44b9-89bc-76eadec60736"
private let pbk = "a0Q1kPTUwrs-ijmXBlQbdYwmWDBCVKTmRGx6lCtqM3o"
private let reality = "vless://\(uuid)@203.0.113.7:443?type=tcp&security=reality&pbk=\(pbk)"
    + "&fp=chrome&sni=www.microsoft.com&sid=a1b2c3d4&spx=%2F&flow=xtls-rprx-vision#NL%20Reality"

private func json(_ link: ProxyLink) throws -> [String: Any] {
    let data = try link.xrayConfiguration(address: "203.0.113.7", interface: "utun12",
                                            gateway: "198.18.0.49/30", mtu: 1500, probePorts: (41000, 41001))
    return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
}

private func outbound(_ root: [String: Any]) throws -> [String: Any] {
    try #require((root["outbounds"] as? [[String: Any]])?.first)
}

@Suite struct ProxyLinkTests {
    @Test func parsesRealityVision() throws {
        let c = try VLESSConfig.parse(reality)
        #expect(c.id == uuid)
        #expect(c.host == "203.0.113.7")
        #expect(c.port == 443)
        #expect(c.remark == "NL Reality")
        #expect(c.stream.transport == .raw)
        #expect(c.stream.security == .reality)
        #expect(c.flow == "xtls-rprx-vision")
        #expect(c.stream.serverName == "www.microsoft.com")
        #expect(c.stream.realityShortID == "a1b2c3d4")
        #expect(c.stream.realitySpiderX == "/")
        #expect(TunnelKind.detect("  \(reality)\n") == .vless)
    }

    @Test func rendersRealityForXray() throws {
        let root = try json(try ProxyLink.parse(reality))
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
        let stream = try #require(try outbound(try json(.vless(c)))["streamSettings"] as? [String: Any])
        #expect((stream["tlsSettings"] as? [String: Any])?["serverName"] as? String == "vpn.example.com")
        let ws = try #require(stream["wsSettings"] as? [String: Any])
        #expect(ws["path"] as? String == "/ws")
        #expect(ws["host"] as? String == "vpn.example.com")
    }

    @Test func xhttpGRPCAndHTTPUpgrade() throws {
        let xhttp = try VLESSConfig.parse("vless://\(uuid)@203.0.113.7:443?type=xhttp&security=reality&pbk=\(pbk)"
            + "&sni=www.microsoft.com&path=%2Fxh&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D")
        let xs = try #require(try outbound(try json(.vless(xhttp)))["streamSettings"] as? [String: Any])
        let settings = try #require(xs["xhttpSettings"] as? [String: Any])
        #expect(settings["mode"] as? String == "packet-up")
        #expect((settings["extra"] as? [String: Any])?["xPaddingBytes"] as? String == "100-1000")

        let grpc = try VLESSConfig.parse("vless://\(uuid)@203.0.113.7:443?type=grpc&security=reality&pbk=\(pbk)"
            + "&serviceName=svc&mode=multi")
        let gs = try #require(try outbound(try json(.vless(grpc)))["streamSettings"] as? [String: Any])
        #expect((gs["grpcSettings"] as? [String: Any])?["serviceName"] as? String == "svc")
        #expect((gs["grpcSettings"] as? [String: Any])?["multiMode"] as? Bool == true)

        let hu = try VLESSConfig.parse("vless://\(uuid)@[2001:db8::1]:80?type=httpupgrade&path=%2Fhu&encryption=none")
        #expect(hu.host == "2001:db8::1")
        #expect(hu.endpoint == "[2001:db8::1]:80")
        let hs = try #require(try outbound(try json(.vless(hu)))["streamSettings"] as? [String: Any])
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
        #expect(c.stream.security == .reality)
    }

    @Test func routingDefaultsToEverythingWithDefaultDNS() throws {
        let routing = try ProxyLink.parse(reality).routing(TunnelSettings())
        #expect(routing.isFullTunnel)
        #expect(routing.ipv4Networks.map(\.description) == ["0.0.0.0/0"])
        #expect(routing.ipv6Networks.map(\.description) == ["::/0"])
        #expect(routing.dnsServers.map(\.description) == ProxyLink.defaultDNS)
    }

    @Test func routingHonoursSettings() throws {
        var s = TunnelSettings()
        s.routing = .onlyListed
        s.networks = ["10.0.0.0/8"]
        s.dnsMode = .custom
        s.dnsServers = ["9.9.9.9"]
        let routing = try ProxyLink.parse(reality).routing(s)
        #expect(!routing.isFullTunnel)
        #expect(routing.networks.map(\.description) == ["10.0.0.0/8"])
        #expect(routing.dnsServers.map(\.description) == ["9.9.9.9"])

        var local = TunnelSettings()
        local.excludeLocalNetworks = true
        let bypass = try ProxyLink.parse(reality).routing(local).bypass.map(\.description)
        #expect(bypass.contains("192.168.0.0/16"))
    }

    // MARK: Trojan

    @Test func trojanDefaultsToTLSAndSharesTransports() throws {
        let link = try ProxyLink.parse("trojan://p%40ss@vpn.example.com:443?type=grpc&serviceName=svc&fp=firefox#DE")
        guard case .trojan(let c) = link else { Issue.record("not trojan"); return }
        #expect(c.password == "p@ss")
        #expect(c.stream.security == .tls)
        #expect(link.kind == .trojan)
        #expect(link.remark == "DE")
        let out = try outbound(try json(link))
        #expect(out["protocol"] as? String == "trojan")
        let server = try #require(((out["settings"] as? [String: Any])?["servers"] as? [[String: Any]])?.first)
        #expect(server["password"] as? String == "p@ss")
        let stream = try #require(out["streamSettings"] as? [String: Any])
        #expect((stream["tlsSettings"] as? [String: Any])?["serverName"] as? String == "vpn.example.com")
        #expect(stream["network"] as? String == "grpc")
        #expect(throws: ConfigError.self) { try ProxyLink.parse("trojan://p@h:443?flow=xtls-rprx-vision") }
    }

    // MARK: Hysteria 2

    @Test func hysteria2WithObfsAndPortHopping() throws {
        let text = "hysteria2://user:secret@hy.example.com:443,20000-30000/?sni=cdn.example.com&obfs=salamander"
            + "&obfs-password=gecko&insecure=0&pinSHA256=" + String(repeating: "ab", count: 32) + "#JP"
        let link = try ProxyLink.parse(text)
        guard case .hysteria2(let c) = link else { Issue.record("not hysteria2"); return }
        #expect(c.auth == "user:secret")
        #expect(c.port == 443)
        #expect(c.usesPortHopping)
        #expect(c.ports.description == "443,20000-30000")
        #expect(link.endpoint == "hy.example.com:443")
        #expect(TunnelKind.detect(text) == .hysteria2)

        let out = try outbound(try json(link))
        #expect(out["protocol"] as? String == "hysteria")
        let settings = try #require(out["settings"] as? [String: Any])
        #expect(settings["version"] as? Int == 2)
        #expect(settings["address"] as? String == "203.0.113.7")
        let stream = try #require(out["streamSettings"] as? [String: Any])
        #expect(stream["network"] as? String == "hysteria")
        #expect((stream["hysteriaSettings"] as? [String: Any])?["auth"] as? String == "user:secret")
        let tls = try #require(stream["tlsSettings"] as? [String: Any])
        #expect(tls["serverName"] as? String == "cdn.example.com")
        #expect(tls["alpn"] as? [String] == ["h3"])
        let masks = try #require((stream["finalmask"] as? [String: Any])?["udp"] as? [[String: Any]])
        #expect(masks.map { $0["type"] as? String } == ["salamander", "udphop"])
        #expect((masks[1]["settings"] as? [String: Any])?["remotePorts"] as? String == "443,20000-30000")
    }

    @Test func hysteria2ShortSchemeDefaultsAndMport() throws {
        let link = try ProxyLink.parse("hy2://pw@203.0.113.9?mport=5000-6000&upmbps=50")
        guard case .hysteria2(let c) = link else { Issue.record("not hysteria2"); return }
        #expect(c.port == 443)
        #expect(c.ports.description == "443,5000-6000")
        #expect(c.upMbps == 50)
        let stream = try #require(try outbound(try json(link))["streamSettings"] as? [String: Any])
        let quic = try #require((stream["finalmask"] as? [String: Any])?["quicParams"] as? [String: Any])
        #expect(quic["congestion"] as? String == "brutal")
        // An IP address is not sent as SNI.
        #expect((stream["tlsSettings"] as? [String: Any])?["serverName"] == nil)
    }

    @Test(arguments: [
        ("hysteria2://pw@h:443?insecure=1", "certificate checks"),
        ("hysteria2://h:443", "password"),
        ("hysteria2://pw@h:443?obfs=salamander", "obfs-password"),
        ("hysteria2://pw@h:443?obfs=other&obfs-password=x", "only salamander"),
        ("hysteria2://pw@h:70000", "port"),
        ("hysteria2://pw@h:443?foo=1", "Unknown parameter"),
        ("hy2://pw@h:443?hopInterval=2", "at least 5"),
    ])
    func hysteria2Rejects(link: String, message: String) {
        #expect {
            try ProxyLink.parse(link)
        } throws: { error in
            "\(error)".contains(message)
        }
    }
}

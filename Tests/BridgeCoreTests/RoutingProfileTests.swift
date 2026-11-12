import Foundation
import Testing
@testable import BridgeCore

/// The RoscomVPN profile as Happ distributes it (strings for booleans, DoH servers).
private let roscom = """
{
  "Name": "RoscomVPN", "GlobalProxy": "true", "UseChunkFiles": "true",
  "RemoteDns": "8.8.8.8", "DomesticDns": "77.88.8.8",
  "RemoteDNSType": "DoH", "RemoteDNSDomain": "https://8.8.8.8/dns-query", "RemoteDNSIP": "8.8.8.8",
  "DomesticDNSType": "DoH", "DomesticDNSDomain": "https://77.88.8.8/dns-query", "DomesticDNSIP": "77.88.8.8",
  "Geoipurl": "https://cdn.example/geoip.dat", "Geositeurl": "https://cdn.example/geosite.dat",
  "LastUpdated": "1794394248",
  "DnsHosts": { "lknpd.nalog.ru": "213.24.64.181" },
  "RouteOrder": "block-proxy-direct",
  "DirectSites": ["geosite:private", "geosite:category-ru"],
  "DirectIp": ["geoip:private", "geoip:direct"],
  "ProxySites": ["geosite:youtube"],
  "ProxyIp": [],
  "BlockSites": ["geosite:category-ads"],
  "BlockIp": [],
  "DomainStrategy": "IPIfNonMatch",
  "FakeDNS": "false"
}
"""

private func rules(_ root: [String: Any]) throws -> [[String: Any]] {
    try #require((root["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
}

@Suite struct RoutingProfileTests {
    @Test func parsesHappFormat() throws {
        let p = try RoutingProfile.parse(roscom)
        #expect(p.name == "RoscomVPN")
        #expect(p.globalProxy)
        #expect(p.remoteDNS == .init(address: "https://8.8.8.8/dns-query", ip: "8.8.8.8"))
        #expect(p.domesticDNS.ip == "77.88.8.8")
        #expect(p.hosts["lknpd.nalog.ru"] == "213.24.64.181")
        #expect(p.order == [.block, .proxy, .direct])
        #expect(p.needsGeoIP && p.needsGeoSite)
        #expect(p.sendsTrafficDirect)
        #expect(p.domainStrategy == "IPIfNonMatch")
    }

    @Test func parsesHappLinks() throws {
        let b64 = Data(roscom.utf8).base64EncodedString()
        #expect(try RoutingProfile.parse("happ://routing/add/\(b64)") == RoutingProfile.parse(roscom))
        #expect(try RoutingProfile.parse("happ://routing/onadd/\(b64)").name == "RoscomVPN")
    }

    @Test(arguments: [
        (#"{"Name":"x","Surprise":1}"#, "Unknown routing profile key"),
        (#"{"Name":"x","FakeDNS":"true"}"#, "FakeDNS"),
        (#"{"Name":"x","RouteOrder":"proxy-direct"}"#, "RouteOrder"),
        (#"{"Name":"x","DirectSites":["ext:custom.dat:x"]}"#, "external rule files"),
        (#"{"Name":"x","DirectIp":["not-an-ip"]}"#, "not an IP"),
        (#"{"Name":"x","RemoteDNSType":"DoQ","RemoteDNSIP":"1.1.1.1"}"#, "not supported"),
        (#"{"Name":"x","DomainStrategy":"Fastest"}"#, "DomainStrategy"),
        ("not json", "JSON object"),
    ])
    func rejects(json: String, message: String) {
        #expect {
            try RoutingProfile.parse(json)
        } throws: { error in
            "\(error)".contains(message)
        }
    }

    @Test func buildsXrayRoutingAndDNS() throws {
        let profile = try RoutingProfile.parse(roscom)
        let link = try ProxyLink.parse("trojan://pw@vpn.example.com:443")
        let data = try link.xrayConfiguration(address: "203.0.113.7", interface: "utun12", gateway: "198.18.0.49/30",
                                              mtu: 1500, probePorts: (1, 2), profile: profile, directInterface: "en0")
        let root = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])

        let outbounds = try #require(root["outbounds"] as? [[String: Any]])
        #expect(outbounds.map { $0["tag"] as? String } == ["proxy", "direct", "block", "dns-out"])
        let direct = try #require(outbounds.first { $0["tag"] as? String == "direct" })
        let sockopt = (direct["streamSettings"] as? [String: Any])?["sockopt"] as? [String: Any]
        #expect(sockopt?["interface"] as? String == "en0")

        let tun = try #require((root["inbounds"] as? [[String: Any]])?.first)
        #expect((tun["sniffing"] as? [String: Any])?["routeOnly"] as? Bool == true)

        let r = try rules(root)
        #expect(r.first?["outboundTag"] as? String == "proxy")  // health checks always use the proxy
        #expect(r.contains { $0["port"] as? String == "53" && $0["outboundTag"] as? String == "dns-out" })
        // RouteOrder: block, then proxy, then direct; finally the default.
        let actions = r.compactMap { rule -> String? in
            rule["domain"] != nil || rule["ip"] != nil && rule["inboundTag"] == nil ? rule["outboundTag"] as? String : nil
        }
        #expect(actions == ["block", "proxy", "direct", "direct"])
        #expect(r.last?["outboundTag"] as? String == "proxy")

        let dns = try #require(root["dns"] as? [String: Any])
        let servers = try #require(dns["servers"] as? [Any])
        let domestic = try #require(servers.first as? [String: Any])
        #expect(domestic["address"] as? String == "https://77.88.8.8/dns-query")
        #expect(domestic["domains"] as? [String] == ["geosite:private", "geosite:category-ru"])
        #expect(servers.last as? String == "https://8.8.8.8/dns-query")
        #expect((dns["hosts"] as? [String: Any])?["lknpd.nalog.ru"] as? String == "213.24.64.181")
    }

    @Test func settingsKeepTheProfileName() throws {
        var settings = TunnelSettings()
        settings.routingProfile = "RoscomVPN"
        let decoded = try JSONDecoder().decode(TunnelSettings.self, from: try JSONEncoder().encode(settings))
        #expect(decoded.routingProfile == "RoscomVPN")
        #expect(!settings.isDefault)
    }
}

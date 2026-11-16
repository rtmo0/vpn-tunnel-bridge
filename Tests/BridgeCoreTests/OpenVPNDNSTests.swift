import Testing
@testable import BridgeCore

@Suite struct OpenVPNDNSTests {
    @Test func pushReplyOptions() throws {
        let message = "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0,"
            + "dns server 0 address 10.0.0.53 [fd00::53]:53,dns server 0 resolve-domains corp.example,"
            + "ifconfig 10.8.0.2 255.255.255.0,peer-id 0'"
        let options = try #require(OpenVPNDNS.pushedOptions(inLogMessage: message))
        #expect(options.first == ["route", "10.0.0.0", "255.0.0.0"])
        let dns = options.filter { $0.first == "dns" }.map { Array($0.dropFirst()) }
        let settings = try #require(OpenVPNDNS.from(dnsOptions: dns))
        #expect(settings.servers == ["10.0.0.53", "fd00::53"])
        #expect(settings.domains == ["corp.example"])
        #expect(settings.splitDomainsOnly)
        #expect(OpenVPNDNS.pushedOptions(inLogMessage: "Initialization Sequence Completed") == nil)
    }

    @Test func dnsOptionsByPriority() throws {
        let settings = try #require(OpenVPNDNS.from(dnsOptions: [
            ["search-domains", "example.com"],
            ["server", "2", "address", "9.9.9.9"],
            ["server", "1", "address", "1.1.1.1:53"],
            ["server", "1", "transport", "DoT"],
        ]))
        #expect(settings.servers == ["1.1.1.1", "9.9.9.9"])
        #expect(settings.domains == ["example.com"])
        #expect(!settings.splitDomainsOnly)
        #expect(OpenVPNDNS.from(dnsOptions: [["search-domains", "a.example"]]) == nil)
    }

    @Test func foreignOptions() throws {
        let settings = try #require(OpenVPNDNS.from(foreignOptions: [
            "foreign_option_1": "dhcp-option DNS 10.8.0.1",
            "foreign_option_2": "dhcp-option DOMAIN corp.example",
            "foreign_option_3": "dhcp-option DNS6 fd00::1",
            "foreign_option_4": "dhcp-option DNS not-an-ip",
        ]))
        #expect(settings.servers == ["10.8.0.1", "fd00::1"])
        #expect(settings.domains == ["corp.example"])
        #expect(OpenVPNDNS.from(foreignOptions: ["foreign_option_1": "dhcp-option DOMAIN x"]) == nil)
    }
}

@Suite struct OpenVPNAllowlistTests {
    private func prepare(_ body: String) throws -> OpenVPNConfig.Prepared {
        try OpenVPNConfig.parse("client\nremote a 1194\n" + body).prepared(tunnel: "t", managementSocket: "/m",
                                                                          eventCommand: "/e")
    }

    @Test func unknownOptionsAreDropped() throws {
        let prepared = try prepare("frobnicate /etc/passwd\ncipher AES-256-GCM\nkeepalive 10 60\n")
        let lines = prepared.text.components(separatedBy: "\n")
        #expect(!lines.contains { $0.hasPrefix("frobnicate") })
        #expect(lines.contains("cipher AES-256-GCM"))
        #expect(lines.contains("keepalive 10 60"))
        #expect(prepared.warnings.contains { $0.contains("frobnicate") })
        // An unknown option marked optional is judged the same way.
        let optional = try prepare("setenv opt frobnicate x\nsetenv opt tls-cipher DEFAULT\n").text
        #expect(!optional.contains("frobnicate"))
        #expect(optional.contains("setenv opt tls-cipher DEFAULT"))
    }

    @Test func connectionBlocksAreFiltered() throws {
        let text = try prepare("<connection>\nremote b 443\nproto tcp\nup /tmp/evil.sh\n</connection>\n").text
        #expect(text.contains("remote b 443"))
        #expect(text.contains("proto tcp"))
        #expect(!text.contains("/tmp/evil.sh"))
        #expect(throws: ConfigError.self) {
            try prepare("<connection>\nremote b 443\nhttp-proxy p 8080 /etc/master.passwd\n</connection>\n")
        }
    }

    @Test func proxyCredentialFilesAreRejected() throws {
        #expect(throws: ConfigError.self) { try prepare("http-proxy p 8080 /var/root/creds\n") }
        #expect(throws: ConfigError.self) { try prepare("socks-proxy p 1080 /var/root/creds\n") }
        #expect(try prepare("http-proxy p 8080\n").text.contains("http-proxy p 8080"))
    }

    @Test func pullFiltersApplyToPushedDNS() {
        let options = [["dns", "server", "0", "address", "10.0.0.1"], ["route", "10.0.0.0", "255.0.0.0"]]
        let kept = OpenVPNDNS.applying(pullFilters: [["ignore", "dns server"]], to: options)
        #expect(kept == [["route", "10.0.0.0", "255.0.0.0"]])
        let accepted = OpenVPNDNS.applying(pullFilters: [["accept", "dns server 0"], ["ignore", "dns"]], to: options)
        #expect(accepted == options)
    }
}

import Foundation
import Testing
@testable import BridgeCore

@Suite struct DirectSitesTests {
    @Test func normalizesWhatPeoplePaste() {
        #expect(DirectSites.normalize("gosuslugi.ru") == "gosuslugi.ru")
        #expect(DirectSites.normalize("  Gosuslugi.RU. ") == "gosuslugi.ru")
        #expect(DirectSites.normalize("https://www.nalog.gov.ru/rn77/?x=1#top") == "www.nalog.gov.ru")
        #expect(DirectSites.normalize("http://user@example.com:8080/") == "example.com")
        #expect(DirectSites.normalize("*.example.com") == "example.com")
        #expect(DirectSites.normalize("госуслуги.рф") == "xn--c1aapkosapc.xn--p1ai")
    }

    @Test func rejectsWhatIsNotADomain() {
        for bad in ["", "localhost", "example", "1.2.3.4", "10.0.0.0/8", "ex ample.com", "-bad.com", "bad-.com",
                    "a..b", "example.123", "fe80::1"] {
            #expect(DirectSites.normalize(bad) == nil, "\(bad)")
        }
    }

    @Test func normalizedListDropsRepeatsAndReportsBadEntries() throws {
        #expect(try DirectSites.normalized(["A.com", "a.com.", "b.com"]) == ["a.com", "b.com"])
        #expect(throws: ConfigError.self) { try DirectSites.normalized(["a.com", "not a domain"]) }
    }

    @Test func hostNamesAddWWW() {
        #expect(DirectSites.hostNames(for: "example.com") == ["example.com", "www.example.com"])
        #expect(DirectSites.hostNames(for: "www.example.com") == ["www.example.com"])
    }

    @Test func neverRoutesLocalOrSpecialAddresses() {
        for ip in ["10.1.2.3", "192.168.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "224.0.0.1", "0.0.0.0",
                   "fe80::1", "fd00::1", "::1", "ff02::1"] {
            #expect(!DirectSites.isRoutable(IPAddress(ip)!), "\(ip)")
        }
        #expect(DirectSites.isRoutable(IPAddress("95.167.1.1")!))
        #expect(DirectSites.isRoutable(IPAddress("2a00:1450:4010::66")!))
    }

    @Test func domainsAreAllowedOnlyWhenExcluding() throws {
        var settings = TunnelSettings()
        settings.routing = .allExceptListed
        settings.networks = ["192.168.50.0/24", "Gosuslugi.ru", "gosuslugi.ru"]
        try settings.validate()
        #expect(settings.directDomains == ["gosuslugi.ru"])
        #expect(settings.parsedNetworks.map(\.description) == ["192.168.50.0/24"])

        settings.routing = .onlyListed
        #expect(settings.directDomains.isEmpty)
        #expect(throws: ConfigError.self) { try settings.validate() }

        settings.routing = .allExceptListed
        settings.networks = ["not a site"]
        #expect(throws: ConfigError.self) { try settings.validate() }
    }

    @Test func domainsOnlyStillRouteEverythingThroughTheTunnel() throws {
        var settings = TunnelSettings()
        settings.routing = .allExceptListed
        settings.networks = ["example.com"]
        let config = try TunnelConfig.parse("""
        [Interface]
        PrivateKey = \(Data(repeating: 1, count: 32).base64EncodedString())
        Address = 10.9.9.6/32
        [Peer]
        PublicKey = \(Data(repeating: 2, count: 32).base64EncodedString())
        Endpoint = 203.0.113.7:51820
        AllowedIPs = 10.0.0.0/8
        """)
        let (applied, bypass) = try config.applying(settings)
        #expect(applied.isFullTunnel)
        #expect(bypass.isEmpty)
    }
}

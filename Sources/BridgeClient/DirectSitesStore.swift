import BridgeCore
import Foundation

/// The global list of sites that go direct while a tunnel takes all traffic, in
/// ~/Library/Application Support/Bridge/direct-sites.json (shared by the app and the CLI).
public enum DirectSitesStore {
    public struct Settings: Codable, Equatable, Sendable {
        public var enabled = false
        public var domains: [String] = []

        public init(enabled: Bool = false, domains: [String] = []) {
            self.enabled = enabled
            self.domains = domains
        }

        /// What the helper gets: nothing while switched off.
        public var active: [String] { enabled ? domains : [] }
    }

    static var url: URL {
        TunnelLibrary.directory.deletingLastPathComponent().appendingPathComponent("direct-sites.json")
    }

    public static func load() -> Settings {
        guard let data = try? Data(contentsOf: url),
              let settings = try? JSONDecoder().decode(Settings.self, from: data) else { return Settings() }
        return settings
    }

    /// Normalizes the domains (punycode, no repeats) and saves; throws for an invalid entry.
    @discardableResult
    public static func save(_ settings: Settings) throws -> Settings {
        var settings = settings
        settings.domains = try DirectSites.normalized(settings.domains)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(settings).write(to: url, options: .atomic)
        return settings
    }
}

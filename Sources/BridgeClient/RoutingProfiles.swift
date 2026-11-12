import BridgeCore
import Foundation

/// Imported routing profiles in ~/Library/Application Support/Bridge/Routing/<name>/:
/// `profile.json` as imported, plus the `geoip.dat` / `geosite.dat` it points to.
public enum RoutingProfiles {
    public static var directory: URL {
        TunnelLibrary.directory.deletingLastPathComponent().appendingPathComponent("Routing", isDirectory: true)
    }

    static let maxAssetSize = 64 << 20

    public static func list() -> [String] {
        let entries = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return entries.filter { FileManager.default.fileExists(atPath: $0.appendingPathComponent("profile.json").path) }
            .map(\.lastPathComponent)
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }

    public static func folder(_ name: String) -> URL { directory.appendingPathComponent(name, isDirectory: true) }

    public static func load(_ name: String) throws -> RoutingProfile {
        let url = folder(name).appendingPathComponent("profile.json")
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            throw ClientError("No routing profile named “\(name)”")
        }
        return try RoutingProfile.parse(text)
    }

    /// Imports `routing.json` text or a `happ://routing/…` link and downloads its geo files.
    /// Re-importing a profile with the same name replaces it.
    @discardableResult
    public static func importProfile(_ text: String) throws -> String {
        let profile = try RoutingProfile.parse(text)
        let name = TunnelName.sanitized(profile.name)
        let staging = directory.appendingPathComponent(".import-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: staging) }

        let json: Data
        if text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("happ://") {
            // Keep the decoded JSON, so the stored file is readable.
            let encoded = text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "/").last.map(String.init) ?? ""
            var b64 = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            while b64.count % 4 != 0 { b64.append("=") }
            json = Data(base64Encoded: b64) ?? Data(text.utf8)
        } else {
            json = Data(text.utf8)
        }
        try json.write(to: staging.appendingPathComponent("profile.json"), options: .atomic)
        try download(profile, into: staging)

        let target = folder(name)
        try? FileManager.default.removeItem(at: target)
        try FileManager.default.moveItem(at: staging, to: target)
        return name
    }

    /// Downloads the geo files again (lists change often).
    public static func update(_ name: String) throws {
        let profile = try load(name)
        try download(profile, into: folder(name))
    }

    public static func remove(_ name: String) throws {
        guard list().contains(name) else { throw ClientError("No routing profile named “\(name)”") }
        try FileManager.default.removeItem(at: folder(name))
        // Tunnels that used it go back to plain routing.
        for tunnel in TunnelLibrary.list() {
            var settings = TunnelLibrary.settings(for: tunnel.name)
            guard settings.routingProfile == name else { continue }
            settings.routingProfile = nil
            try? TunnelLibrary.saveSettings(settings, for: tunnel.name)
        }
    }

    /// Fails when a file the profile's rules need is missing.
    public static func checkAssets(_ profile: RoutingProfile, name: String) throws {
        for (needed, file) in [(profile.needsGeoIP, "geoip.dat"), (profile.needsGeoSite, "geosite.dat")] where needed {
            guard FileManager.default.fileExists(atPath: folder(name).appendingPathComponent(file).path) else {
                throw ClientError("Routing profile “\(name)” is missing \(file). Update the profile to download it.")
            }
        }
    }

    private static func download(_ profile: RoutingProfile, into folder: URL) throws {
        for (needed, source, file) in [(profile.needsGeoIP, profile.geoipURL, "geoip.dat"),
                                       (profile.needsGeoSite, profile.geositeURL, "geosite.dat")] where needed {
            guard let source, let url = URL(string: source), url.scheme?.lowercased() == "https" else {
                throw ClientError("The profile uses \(file) rules but has no https:// address to download it from")
            }
            let data = try fetch(url)
            guard !data.isEmpty, data.count <= maxAssetSize else {
                throw ClientError("\(file) from \(url.host ?? "the server") has an unexpected size (\(data.count) bytes)")
            }
            try data.write(to: folder.appendingPathComponent(file), options: .atomic)
        }
    }

    private static func fetch(_ url: URL) throws -> Data {
        final class Box: @unchecked Sendable { var result: Result<Data, Error> = .failure(ClientError("Timed out")) }
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        var request = URLRequest(url: url, timeoutInterval: 60)
        request.setValue("Bridge", forHTTPHeaderField: "User-Agent")
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error {
                box.result = .failure(ClientError("Could not download \(url.lastPathComponent): \(error.localizedDescription)"))
            } else if let http = response as? HTTPURLResponse, http.statusCode != 200 {
                box.result = .failure(ClientError("Could not download \(url.lastPathComponent): HTTP \(http.statusCode)"))
            } else {
                box.result = .success(data ?? Data())
            }
            done.signal()
        }.resume()
        done.wait()
        return try box.result.get()
    }
}

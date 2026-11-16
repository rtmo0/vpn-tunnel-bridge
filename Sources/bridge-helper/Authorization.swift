import BridgeCore
import Foundation
import Security

/// Settings that belong to the helper (root-owned, so another app cannot change them).
struct HelperSettings: Codable {
    var requireAuthorization = false

    static let directory = "/Library/Application Support/com.rtmo0.bridge.helper"
    static var path: String { "\(directory)/settings.json" }

    private static let lock = NSLock()
    private static var cached: HelperSettings?

    static var current: HelperSettings {
        lock.withLock {
            if let cached { return cached }
            let loaded = FileManager.default.contents(atPath: path)
                .flatMap { try? JSONDecoder().decode(HelperSettings.self, from: $0) } ?? HelperSettings()
            cached = loaded
            return loaded
        }
    }

    static func save(_ settings: HelperSettings) throws {
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        try JSONEncoder().encode(settings).write(to: URL(fileURLWithPath: path), options: .atomic)
        chmod(path, 0o644)
        lock.withLock { cached = settings }
    }
}

/// Checks the authorization a client sends for tunnel changes.
///
/// The client obtains `HelperProtocol.controlRight` itself (macOS asks the user for
/// the password) and sends its external form. The helper never shows a dialog: it only
/// checks that the authorization already holds the right, so a program that wants to
/// change tunnels has to ask the user openly.
enum ControlAuthorization {
    static func isValid(_ data: Data?) -> Bool {
        guard let data, data.count == MemoryLayout<AuthorizationExternalForm>.size else { return false }
        var form = AuthorizationExternalForm()
        withUnsafeMutableBytes(of: &form) { _ = data.copyBytes(to: $0) }
        var reference: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&form, &reference) == errAuthorizationSuccess,
              let reference else { return false }
        defer { AuthorizationFree(reference, []) }
        return HelperProtocol.controlRight.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                return AuthorizationCopyRights(reference, &rights, nil, [.extendRights], nil) == errAuthorizationSuccess
            }
        }
    }
}

import Foundation
import Security

/// Stores OpenVPN credentials in the user's login keychain.
public enum Keychain {
    static let service = "com.rtmo0.bridge"

    private struct Credentials: Codable {
        var username: String
        var password: String
    }

    private static func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    private static func set(_ data: Data, account: String, label: String) throws {
        SecItemDelete(query(account) as CFDictionary)
        var item = query(account)
        item[kSecValueData as String] = data
        item[kSecAttrLabel as String] = label
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw ClientError("Could not save to Keychain (\(SecCopyErrorMessageString(status, nil) as String? ?? "\(status)"))")
        }
    }

    private static func get(_ account: String) -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    public static func saveCredentials(username: String, password: String, for tunnel: String) throws {
        let data = try JSONEncoder().encode(Credentials(username: username, password: password))
        try set(data, account: "\(tunnel)/auth", label: "Bridge: \(tunnel)")
    }

    public static func credentials(for tunnel: String) -> (username: String, password: String)? {
        guard let data = get("\(tunnel)/auth"),
              let c = try? JSONDecoder().decode(Credentials.self, from: data) else { return nil }
        return (c.username, c.password)
    }

    public static func savePassphrase(_ passphrase: String, for tunnel: String) throws {
        try set(Data(passphrase.utf8), account: "\(tunnel)/key", label: "Bridge: \(tunnel) (private key)")
    }

    public static func passphrase(for tunnel: String) -> String? {
        get("\(tunnel)/key").map { String(decoding: $0, as: UTF8.self) }
    }

    public static func deleteCredentials(for tunnel: String) { SecItemDelete(query("\(tunnel)/auth") as CFDictionary) }
    public static func deletePassphrase(for tunnel: String) { SecItemDelete(query("\(tunnel)/key") as CFDictionary) }

    public static func deleteAll(for tunnel: String) {
        deleteCredentials(for: tunnel)
        deletePassphrase(for: tunnel)
    }
}

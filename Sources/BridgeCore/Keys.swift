import Foundation

/// Helpers for WireGuard-style 32-byte keys.
public enum WireGuardKey {
    public static let length = 32

    /// Decodes a base64 key (as written in .conf files) into raw bytes.
    public static func decode(base64 value: String) -> Data? {
        guard let data = Data(base64Encoded: value.trimmingCharacters(in: .whitespaces)),
              data.count == length else { return nil }
        return data
    }

    /// Converts a base64 key into the lowercase hex form used by the UAPI protocol.
    public static func hex(fromBase64 value: String) -> String? {
        decode(base64: value).map(hexString)
    }

    /// Converts a UAPI hex key back into base64.
    public static func base64(fromHex hex: String) -> String? {
        guard hex.count == length * 2 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(length)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return Data(bytes).base64EncodedString()
    }

    public static func hexString(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

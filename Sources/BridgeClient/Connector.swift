import BridgeCore
import Foundation

public enum HelperClient {
    public static func send(_ request: HelperRequest, timeout: Int = 90) throws -> HelperResponse {
        let fd: Int32
        do {
            fd = try UnixSocket.connect(path: HelperProtocol.socketPath, timeout: timeout)
        } catch {
            throw ClientError("The Bridge helper is not running (\(error)).")
        }
        defer { close(fd) }
        let data = try JSONEncoder.bridge.encode(request)
        try UnixSocket.writeAll(fd, String(decoding: data, as: UTF8.self) + "\n")
        let line = try UnixSocket.read(fd, until: "\n", limit: 4 << 20)
        guard !line.isEmpty else { throw ClientError("The Bridge helper closed the connection.") }
        return try JSONDecoder.bridge.decode(HelperResponse.self, from: Data(line.utf8))
    }

    /// Sends a request and throws if the helper reports a failure.
    @discardableResult
    public static func call(_ request: HelperRequest, timeout: Int = 90) throws -> HelperResponse {
        let response = try send(request, timeout: timeout)
        guard response.ok else {
            throw ClientError(response.error ?? "Unknown helper error", code: response.errorCode)
        }
        return response
    }

    public enum Availability: Equatable, Sendable {
        case ready(capabilities: [TunnelKind])
        case outdated(installed: Int)
        case notInstalled
    }

    public static func availability() -> Availability {
        guard let response = try? send(HelperRequest(command: .ping), timeout: 3) else { return .notInstalled }
        let version = response.helperVersion ?? 1
        if version != HelperProtocol.version { return .outdated(installed: version) }
        return .ready(capabilities: response.capabilities ?? [.amneziawg, .wireguard])
    }

    public static func statuses() throws -> [TunnelStatus] {
        try call(HelperRequest(command: .status), timeout: 10).tunnels ?? []
    }

    public static func disconnect(_ name: String) throws {
        try call(HelperRequest(command: .down, name: name), timeout: 30)
    }
}

/// What the connector needs from the user.
public enum SecretPrompt: Sendable {
    case usernamePassword(tunnel: String, username: String?, retry: Bool)
    case keyPassphrase(tunnel: String, retry: Bool)
    case challenge(tunnel: String, text: String, echo: Bool)
}

public struct SecretAnswer: Sendable {
    public var username: String
    /// Password, key passphrase, or challenge response depending on the prompt.
    public var secret: String
    public var remember: Bool

    public init(username: String = "", secret: String, remember: Bool) {
        self.username = username
        self.secret = secret
        self.remember = remember
    }
}

/// Connects a tunnel, asking for and remembering OpenVPN credentials as needed.
public enum Connector {
    /// - Parameter ask: returns nil when the user cancels. May be called from a background thread.
    public static func connect(name: String, text: String, kind: TunnelKind,
                               embedded: OpenVPNConfig.EmbeddedSecrets = .init(),
                               settings: TunnelSettings? = nil,
                               ask: (SecretPrompt) -> SecretAnswer?) throws -> TunnelStatus {
        let settings = settings ?? TunnelLibrary.settings(for: name)
        var secrets = TunnelSecrets()
        var rememberAuth = false
        var rememberKey = false
        var challenge: (text: String, echo: Bool)?

        func cancelled() -> ClientError { ClientError("Cancelled") }

        func askCredentials(retry: Bool) throws {
            guard let answer = ask(.usernamePassword(tunnel: name, username: secrets.username, retry: retry)) else {
                throw cancelled()
            }
            secrets.username = answer.username
            secrets.password = answer.secret
            rememberAuth = answer.remember
        }
        func askPassphrase(retry: Bool) throws {
            guard let answer = ask(.keyPassphrase(tunnel: name, retry: retry)) else { throw cancelled() }
            secrets.keyPassphrase = answer.secret
            rememberKey = answer.remember
        }
        func askChallenge() throws {
            guard let challenge else { return }
            guard let answer = ask(.challenge(tunnel: name, text: challenge.text, echo: challenge.echo)) else {
                throw cancelled()
            }
            secrets.challengeResponse = answer.secret
        }

        if kind == .openvpn {
            let config = try OpenVPNConfig.parse(text)
            challenge = config.staticChallenge
            if config.needsUsernamePassword {
                if let user = embedded.username, let pass = embedded.password {
                    secrets.username = user
                    secrets.password = pass
                } else if let saved = Keychain.credentials(for: name) {
                    secrets.username = saved.username
                    secrets.password = saved.password
                } else {
                    try askCredentials(retry: false)
                }
            }
            if let passphrase = embedded.keyPassphrase ?? Keychain.passphrase(for: name) {
                secrets.keyPassphrase = passphrase
            } else if config.hasEncryptedPrivateKey {
                try askPassphrase(retry: false)
            }
            try askChallenge()
        }

        var lastError = ClientError("Could not connect")
        for _ in 0..<4 {
            let response = try HelperClient.send(
                HelperRequest(command: .up, name: name, config: text, secrets: kind == .openvpn ? secrets : nil,
                              settings: settings.isDefault ? nil : settings))
            if response.ok, let status = response.tunnels?.first {
                if rememberAuth, let user = secrets.username, let pass = secrets.password {
                    try? Keychain.saveCredentials(username: user, password: pass, for: name)
                }
                if rememberKey, let passphrase = secrets.keyPassphrase {
                    try? Keychain.savePassphrase(passphrase, for: name)
                }
                return status
            }
            lastError = ClientError(response.error ?? "Could not connect", code: response.errorCode)
            switch response.errorCode {
            case .authenticationFailed:
                Keychain.deleteCredentials(for: name)
                try askCredentials(retry: true)
                try askChallenge()
            case .credentialsRequired:
                try askCredentials(retry: false)
            case .keyPassphraseFailed:
                Keychain.deletePassphrase(for: name)
                try askPassphrase(retry: true)
            case .keyPassphraseRequired:
                try askPassphrase(retry: false)
            case .challengeRequired:
                challenge = (response.errorDetail ?? "Enter the verification code", true)
                try askChallenge()
            default:
                throw lastError
            }
        }
        throw lastError
    }
}

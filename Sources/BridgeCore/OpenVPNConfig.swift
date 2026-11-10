import Foundation

/// An OpenVPN client configuration (.ovpn), parsed into directives.
///
/// Bridge sends only self-contained configs to the helper: referenced files are
/// inlined on the client side, and the helper strips every directive that could
/// run commands or touch the file system as root.
public struct OpenVPNConfig: Equatable, Sendable {
    public struct Directive: Equatable, Sendable {
        public var name: String
        public var args: [String]
        /// Content of an inline block such as `<ca>…</ca>`.
        public var inline: String?

        public init(name: String, args: [String] = [], inline: String? = nil) {
            self.name = name
            self.args = args
            self.inline = inline
        }
    }

    public var directives: [Directive]

    public init(directives: [Directive]) { self.directives = directives }

    // MARK: Parsing

    public static func parse(_ text: String) throws -> OpenVPNConfig {
        var directives: [Directive] = []
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
        var index = 0
        while index < lines.count {
            let line = lines[index].trimmingCharacters(in: .whitespaces)
            index += 1
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }

            if line.hasPrefix("<") && line.hasSuffix(">") && !line.hasPrefix("</") {
                let tag = String(line.dropFirst().dropLast()).lowercased()
                var content: [String] = []
                var closed = false
                while index < lines.count {
                    let inner = lines[index]
                    index += 1
                    if inner.trimmingCharacters(in: .whitespaces).lowercased() == "</\(tag)>" {
                        closed = true
                        break
                    }
                    content.append(inner)
                }
                guard closed else { throw ConfigError("Inline block <\(tag)> is not closed", line: index) }
                directives.append(Directive(name: tag, inline: content.joined(separator: "\n")))
                continue
            }

            var tokens = try tokenize(line, line: index)
            guard !tokens.isEmpty else { continue }
            var name = tokens.removeFirst().lowercased()
            if name.hasPrefix("--") { name.removeFirst(2) }
            directives.append(Directive(name: name, args: tokens))
        }
        let config = OpenVPNConfig(directives: directives)
        guard config.has("remote") || config.directives.contains(where: { $0.name == "connection" }) else {
            throw ConfigError("Not an OpenVPN client config: no 'remote' server")
        }
        return config
    }

    static func tokenize(_ line: String, line number: Int) throws -> [String] {
        var tokens: [String] = []
        var current = ""
        var inToken = false
        var quote: Character?
        var escape = false
        for ch in line {
            if escape {
                current.append(ch)
                escape = false
                continue
            }
            if let q = quote {
                if ch == q {
                    quote = nil
                } else if ch == "\\" && q == "\"" {
                    escape = true
                } else {
                    current.append(ch)
                }
                continue
            }
            switch ch {
            case "\"", "'":
                quote = ch
                inToken = true
            case "\\":
                escape = true
                inToken = true
            case "#", ";":
                // A comment starts only at the beginning of a token.
                if inToken { current.append(ch) } else { return tokens }
            case _ where ch.isWhitespace:
                if inToken {
                    tokens.append(current)
                    current = ""
                    inToken = false
                }
            default:
                current.append(ch)
                inToken = true
            }
        }
        guard quote == nil else { throw ConfigError("Unterminated quote", line: number) }
        if inToken { tokens.append(current) }
        return tokens
    }

    // MARK: Queries

    public func has(_ name: String) -> Bool { directives.contains { $0.name == name } }
    public func first(_ name: String) -> Directive? { directives.first { $0.name == name } }

    public var remotes: [String] {
        directives.filter { $0.name == "remote" }.map { $0.args.prefix(2).joined(separator: ":") }
    }

    public var needsUsernamePassword: Bool { has("auth-user-pass") }

    /// `static-challenge "text" echo [format]`
    public var staticChallenge: (text: String, echo: Bool)? {
        guard let d = first("static-challenge"), let text = d.args.first else { return nil }
        return (text, d.args.count > 1 && d.args[1] == "1")
    }

    public var hasEncryptedPrivateKey: Bool {
        guard let key = first("key")?.inline else { return false }
        return key.contains("ENCRYPTED")
    }

    public var redirectsGateway: Bool { has("redirect-gateway") }

    // MARK: Inlining (client side)

    /// Files OpenVPN may reference. Value: whether the file is binary (base64 when inlined).
    static let fileDirectives: [String: Bool] = [
        "ca": false, "cert": false, "key": false, "extra-certs": false, "dh": false,
        "tls-auth": false, "tls-crypt": false, "tls-crypt-v2": false, "crl-verify": false,
        "secret": false, "pkcs12": true,
    ]

    public struct EmbeddedSecrets: Equatable, Sendable {
        public var username: String?
        public var password: String?
        public var keyPassphrase: String?

        public init(username: String? = nil, password: String? = nil, keyPassphrase: String? = nil) {
            self.username = username
            self.password = password
            self.keyPassphrase = keyPassphrase
        }
    }

    /// Replaces file references with inline blocks so the config is self-contained.
    /// Credentials from `auth-user-pass <file>` / `askpass <file>` are returned separately.
    public func inliningFiles(relativeTo base: URL) throws -> (OpenVPNConfig, EmbeddedSecrets) {
        var out: [Directive] = []
        var secrets = EmbeddedSecrets()

        func read(_ path: String) throws -> Data {
            let url = path.hasPrefix("/") ? URL(fileURLWithPath: path)
                : base.appendingPathComponent((path as NSString).expandingTildeInPath)
            do {
                return try Data(contentsOf: url)
            } catch {
                throw ConfigError("Cannot read file '\(path)' referenced by the config")
            }
        }

        for directive in directives {
            if let binary = Self.fileDirectives[directive.name], directive.inline == nil,
               let path = directive.args.first, path != "[inline]" {
                if directive.name == "crl-verify" && directive.args.count > 1 {
                    throw ConfigError("crl-verify with a directory is not supported")
                }
                let data = try read(path)
                let content = binary ? data.base64EncodedString(options: .lineLength76Characters)
                    : String(decoding: data, as: UTF8.self).trimmingCharacters(in: .newlines)
                out.append(Directive(name: directive.name, inline: content))
                if (directive.name == "tls-auth" || directive.name == "secret"), directive.args.count > 1 {
                    out.append(Directive(name: "key-direction", args: [directive.args[1]]))
                }
                continue
            }
            if directive.name == "auth-user-pass", let path = directive.args.first, path != "[inline]" {
                let lines = String(decoding: try read(path), as: UTF8.self)
                    .components(separatedBy: .newlines)
                secrets.username = lines.first.map { $0.trimmingCharacters(in: .whitespaces) }
                if lines.count > 1 { secrets.password = lines[1] }
                out.append(Directive(name: "auth-user-pass"))
                continue
            }
            if directive.name == "auth-user-pass", let block = directive.inline {
                let lines = block.components(separatedBy: .newlines)
                secrets.username = lines.first
                if lines.count > 1 { secrets.password = lines[1] }
                out.append(Directive(name: "auth-user-pass"))
                continue
            }
            if directive.name == "askpass" {
                if let path = directive.args.first {
                    secrets.keyPassphrase = String(decoding: try read(path), as: UTF8.self)
                        .components(separatedBy: .newlines).first
                }
                continue
            }
            out.append(directive)
        }
        return (OpenVPNConfig(directives: out), secrets)
    }

    // MARK: Hardening (helper side)

    /// Directives that run programs, write files or would fight with Bridge.
    static let strippedDirectives: Set<String> = [
        "up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify", "auth-user-pass-verify",
        "client-connect", "client-disconnect", "learn-address", "plugin", "script-security", "up-delay",
        "up-restart", "down-pre", "daemon", "log", "log-append", "syslog", "cd", "chroot", "writepid",
        "status", "status-version", "user", "group", "dev", "dev-type", "dev-node", "tmp-dir", "iproute",
        "dns-updown", "management", "askpass", "auth-user-pass-optional", "machine-readable-output",
        // Windows-only options found in many provider configs.
        "block-outside-dns", "register-dns", "dhcp-release", "dhcp-renew", "ip-win32", "route-method",
        "tap-sleep", "windows-driver", "win-sys", "allow-nonadmin", "service",
    ]

    public struct Prepared: Sendable {
        public var text: String
        public var warnings: [String]
    }

    /// Validates a self-contained config and appends the directives Bridge needs.
    /// - Parameters:
    ///   - eventCommand: command run for route-up / down (gets " up" / " down" appended).
    ///   - dnsCommand: single executable OpenVPN 2.7 runs as `dns-updown`; it receives the
    ///     DNS servers and domains (pushed or configured) in its environment.
    public func prepared(tunnel: String, managementSocket: String, eventCommand: String,
                         dnsCommand: String? = nil) throws -> Prepared {
        var kept: [Directive] = []
        var stripped = Set<String>()

        for directive in directives {
            let name = directive.name
            if name == "config" { throw ConfigError("Including other files ('config') is not supported") }
            if name == "dev", let dev = directive.args.first?.lowercased(), dev.hasPrefix("tap") {
                throw ConfigError("TAP (layer 2) tunnels are not supported on macOS; only 'dev tun' works")
            }
            if name == "dev-type", directive.args.first?.lowercased() == "tap" {
                throw ConfigError("TAP (layer 2) tunnels are not supported on macOS; only 'dev tun' works")
            }
            if name == "setenv", directive.args.first == "opt", directive.args.count > 1,
               Self.strippedDirectives.contains(directive.args[1].lowercased()) {
                stripped.insert(directive.args[1].lowercased())
                continue
            }
            if Self.strippedDirectives.contains(name) || name.hasPrefix("management-") {
                stripped.insert(name)
                continue
            }
            if Self.fileDirectives[name] != nil, directive.inline == nil, directive.args.first != "[inline]" {
                throw ConfigError("'\(name)' must be inline. Import the config with Bridge so files are embedded.")
            }
            if name == "auth-user-pass", !directive.args.isEmpty {
                throw ConfigError("'auth-user-pass' must not reference a file here")
            }
            kept.append(directive)
        }

        var text = OpenVPNConfig(directives: kept).render()
        text += """

        # ---- added by Bridge ----
        dev tun
        management \(Self.quote(managementSocket)) unix
        management-hold
        management-query-passwords
        script-security 2
        route-up \(Self.quote("\(eventCommand) up"))
        down \(Self.quote("\(eventCommand) down"))
        setenv BRIDGE_TUNNEL \(Self.quote(tunnel))
        \(dnsCommand.map { "dns-updown \(Self.quote($0))" } ?? "dns-updown disable")
        verb 3

        """

        var warnings: [String] = []
        let scripts = stripped.intersection(["up", "down", "route-up", "route-pre-down", "plugin",
                                             "tls-verify", "ipchange", "client-connect", "learn-address"])
        if !scripts.isEmpty {
            warnings.append("Ignored \(scripts.sorted().joined(separator: ", ")): Bridge never runs scripts from config files.")
        }
        let windows = stripped.intersection(["block-outside-dns", "register-dns", "dhcp-release", "dhcp-renew",
                                             "ip-win32", "route-method", "tap-sleep", "windows-driver"])
        if !windows.isEmpty {
            warnings.append("Ignored Windows-only options: \(windows.sorted().joined(separator: ", ")).")
        }
        return Prepared(text: text, warnings: warnings)
    }

    // MARK: Rendering

    public func render() -> String {
        var lines: [String] = []
        for directive in directives {
            if let inline = directive.inline {
                lines.append("<\(directive.name)>")
                lines.append(inline)
                lines.append("</\(directive.name)>")
            } else {
                lines.append(([directive.name] + directive.args.map(Self.quote)).joined(separator: " "))
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    static func quote(_ value: String) -> String {
        let special = CharacterSet.whitespaces.union(CharacterSet(charactersIn: "\"'\\#;"))
        guard value.isEmpty || value.rangeOfCharacter(from: special) != nil else { return value }
        let escaped = value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        return "\"\(escaped)\""
    }
}

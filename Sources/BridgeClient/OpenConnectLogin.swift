import BridgeCore
import Foundation

/// A login form an OpenConnect server sent (group, username, password, one-time code…).
public struct OpenConnectForm: Sendable {
    public struct Field: Sendable {
        public enum Kind: String, Sendable { case text, password, select, token, hidden }
        public var name: String
        public var label: String
        public var kind: Kind
        public var value: String?
        public var options: [(name: String, label: String)]
        public var numeric: Bool

        public var isVisible: Bool { kind != .hidden }
        /// Looks like the account name / password, so the Keychain can fill it in.
        public var isUsername: Bool { kind == .text && ["username", "user", "login", "uname"].contains(name.lowercased()) }
        public var isPassword: Bool { kind == .password && ["password", "passwd", "pass"].contains(name.lowercased()) }
    }

    public var banner: String?
    public var message: String?
    public var error: String?
    public var fields: [Field]
}

/// One page load in the SSO web view: OpenConnect decides from these when the login is done.
public struct OpenConnectWebPage: Sendable {
    public var url: String
    public var cookies: [(name: String, value: String)]
    public var headers: [(name: String, value: String)]

    public init(url: String, cookies: [(name: String, value: String)], headers: [(name: String, value: String)]) {
        self.url = url
        self.cookies = cookies
        self.headers = headers
    }
}

/// What a login needs from the user. Methods are called from a background thread;
/// the blocking ones wait for an answer.
public protocol OpenConnectLoginUI: AnyObject {
    /// Values by field name, or nil when the user cancels. `remember` asks to keep the password.
    func fill(_ form: OpenConnectForm, tunnel: String) -> (values: [String: String], remember: Bool)?
    /// The server certificate isn't trusted by the system (e.g. self-signed): accept it?
    func trust(tunnel: String, server: String, fingerprint: String, reason: String, details: String?) -> Bool
    /// SAML / SSO in the system browser (the server sends it back to localhost).
    func openBrowser(_ url: URL)
    /// SSO in an embedded web view: report every page load to `onPage`; `onCancel` if closed.
    func startWebLogin(tunnel: String, url: URL, onPage: @escaping @Sendable (OpenConnectWebPage) -> Void,
                       onCancel: @escaping @Sendable () -> Void)
    func finishWebLogin()
}

/// Logs in to an OpenConnect server as the user (through `bridge-openconnect-auth`)
/// and returns the session the helper connects with.
public enum OpenConnectLogin {
    public struct Session: Sendable {
        public var cookie: String
        public var fingerprint: String
        public var connectURL: String?
        public var resolve: String?
    }

    /// Where the login helper lives: inside Bridge.app, or next to the installed helper (for the CLI).
    public static var executablePath: String? {
        var candidates: [String] = []
        if let override = ProcessInfo.processInfo.environment["BRIDGE_OPENCONNECT_AUTH"] { candidates.append(override) }
        if let resources = Bundle.main.resourceURL { candidates.append(resources.appendingPathComponent("bridge-openconnect-auth").path) }
        candidates.append("\(HelperProtocol.installDirectory)/bridge-openconnect-auth")
        candidates.append("/Applications/Bridge.app/Contents/Resources/bridge-openconnect-auth")
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// - Returns: the session, and the username/password typed (to save in the Keychain) when asked to remember.
    public static func run(config: OpenConnectConfig, tunnel: String, ui: OpenConnectLoginUI)
        throws -> (session: Session, remembered: (username: String, password: String)?) {
        guard let path = executablePath else {
            throw ClientError("OpenConnect is not installed with this Bridge build", code: .unsupported)
        }
        var arguments = ["--protocol", config.vpnProtocol.rawValue, "--url", config.url]
        if let group = config.group { arguments += ["--group", group] }
        if let pin = config.serverCert { arguments += ["--servercert", pin] }
        if let ua = config.userAgent { arguments += ["--useragent", ua] }
        if let os = config.reportedOS { arguments += ["--os", os] }

        // A client certificate goes to a private temporary folder for the duration of the login.
        var tempFolder: URL?
        defer { if let tempFolder { try? FileManager.default.removeItem(at: tempFolder) } }
        if let certificate = config.certificate {
            let folder = FileManager.default.temporaryDirectory.appendingPathComponent("bridge-oc-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            tempFolder = folder
            func write(_ text: String, _ file: String) throws -> String {
                let url = folder.appendingPathComponent(file)
                let data = text.contains("-----BEGIN") ? Data(text.utf8) : (Data(base64Encoded: text) ?? Data(text.utf8))
                FileManager.default.createFile(atPath: url.path, contents: data, attributes: [.posixPermissions: 0o600])
                return url.path
            }
            arguments += ["--cert", try write(certificate, certificate.contains("-----BEGIN") ? "cert.pem" : "cert.p12")]
            if let key = config.key { arguments += ["--key", try write(key, "key.pem")] }
        }

        // Servers like ocserv end the login after one wrong password, so a rejected
        // password starts a fresh login rather than retrying the dead one.
        var note: String?
        for _ in 0..<3 {
            do {
                return try attempt(path: path, arguments: arguments, config: config, tunnel: tunnel, ui: ui, note: note)
            } catch let retry as RetryLogin {
                note = retry.message
            }
        }
        throw ClientError("Too many failed sign-in attempts", code: .authenticationFailed)
    }

    private struct RetryLogin: Error { let message: String }

    private static func attempt(path: String, arguments: [String], config: OpenConnectConfig, tunnel: String,
                                ui: OpenConnectLoginUI, note: String?)
        throws -> (session: Session, remembered: (username: String, password: String)?) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        let input = Pipe(), output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        defer { if process.isRunning { process.terminate() } }

        let writer = LineWriter(input.fileHandleForWriting)
        let reader = LineReader(output.fileHandleForReading)
        let saved = Keychain.credentials(for: tunnel)
        var autoFilled = false
        var typedPassword = false
        var pendingNote = note
        var typed: (username: String, password: String, remember: Bool)?
        var log: [String] = []

        @Sendable func b64(_ s: String) -> String { Data(s.utf8).base64EncodedString() }

        while let line = reader.next() {
            guard let message = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  let type = message["type"] as? String else { continue }
            switch type {
            case "log":
                if let text = message["text"] as? String { log.append(text) }
            case "cert":
                let accepted = ui.trust(tunnel: tunnel, server: config.host,
                                        fingerprint: message["fingerprint"] as? String ?? "?",
                                        reason: message["reason"] as? String ?? "",
                                        details: message["details"] as? String)
                writer.send(accepted ? "accept" : "reject")
            case "form":
                var form = parseForm(message)
                if let text = pendingNote, form.fields.contains(where: \.isPassword) {
                    form.error = [text, form.error].compactMap { $0 }.joined(separator: "\n")
                    pendingNote = nil
                }
                for i in form.fields.indices where form.fields[i].isUsername && (form.fields[i].value ?? "").isEmpty {
                    form.fields[i].value = config.username ?? saved?.username
                }
                let visible = form.fields.filter(\.isVisible)
                let fillable = visible.allSatisfy { $0.isUsername || $0.isPassword || ($0.kind == .select && $0.value != nil) }
                var values: [String: String]
                var remember = false
                if let saved, !autoFilled, form.error == nil, fillable, visible.contains(where: \.isPassword) {
                    // The Keychain answers the usual username + password form once; never retry it blindly.
                    autoFilled = true
                    values = [:]
                    for field in visible {
                        if field.isUsername { values[field.name] = field.value ?? saved.username }
                        if field.isPassword { values[field.name] = saved.password }
                    }
                } else {
                    guard let answer = ui.fill(form, tunnel: tunnel) else {
                        writer.send("cancel")
                        continue
                    }
                    values = answer.values
                    remember = answer.remember
                    if form.fields.contains(where: \.isPassword) { typedPassword = true }
                }
                for field in form.fields {
                    if let value = values[field.name] ?? (field.kind == .select ? field.value : nil) {
                        writer.send("set \(b64(field.name)) \(b64(value))")
                    }
                }
                if let password = form.fields.first(where: \.isPassword).flatMap({ values[$0.name] }) {
                    let user = form.fields.first(where: \.isUsername).flatMap { values[$0.name] ?? $0.value }
                        ?? typed?.username ?? config.username ?? saved?.username ?? ""
                    typed = (user, password, remember)
                } else if let user = form.fields.first(where: \.isUsername).flatMap({ values[$0.name] }) {
                    typed = (user, typed?.password ?? "", remember)
                }
                writer.send("submit")
            case "browser":
                if let url = (message["url"] as? String).flatMap(URL.init(string:)) { ui.openBrowser(url) }
            case "webview":
                guard let url = (message["url"] as? String).flatMap(URL.init(string:)) else {
                    writer.send("cancel")
                    continue
                }
                ui.startWebLogin(tunnel: tunnel, url: url, onPage: { page in
                    var parts = ["load", b64(page.url), String(page.cookies.count)]
                    for cookie in page.cookies { parts += [b64(cookie.name), b64(cookie.value)] }
                    parts.append(String(page.headers.count))
                    for header in page.headers { parts += [b64(header.name), b64(header.value)] }
                    writer.send(parts.joined(separator: " "))
                }, onCancel: { writer.send("cancel") })
            case "webview-done":
                ui.finishWebLogin()
            case "done":
                ui.finishWebLogin()
                guard let cookie = message["cookie"] as? String, let fingerprint = message["fingerprint"] as? String else {
                    throw ClientError("The server did not return a session")
                }
                process.waitUntilExit()
                let session = Session(cookie: cookie, fingerprint: fingerprint,
                                      connectURL: message["connect_url"] as? String,
                                      resolve: message["resolve"] as? String)
                let remembered = typed.flatMap { $0.remember && !$0.password.isEmpty ? ($0.username, $0.password) : nil }
                return (session, remembered)
            case "cancelled":
                ui.finishWebLogin()
                throw ClientError("Cancelled")
            case "error":
                ui.finishWebLogin()
                if autoFilled { Keychain.deleteCredentials(for: tunnel) }
                if typedPassword || autoFilled {
                    throw RetryLogin(message: autoFilled ? "The saved password was rejected." : "Wrong username or password.")
                }
                let detail = log.suffix(3).joined(separator: "\n")
                throw ClientError((message["message"] as? String ?? "Login failed")
                                  + (detail.isEmpty ? "" : "\n\(detail)"), code: .authenticationFailed)
            default:
                break
            }
        }
        ui.finishWebLogin()
        throw ClientError("Login ended unexpectedly" + (log.isEmpty ? "" : ":\n" + log.suffix(3).joined(separator: "\n")))
    }

    static func parseForm(_ message: [String: Any]) -> OpenConnectForm {
        let fields = (message["fields"] as? [[String: Any]] ?? []).map { f in
            OpenConnectForm.Field(
                name: f["name"] as? String ?? "",
                label: (f["label"] as? String ?? f["name"] as? String ?? "").trimmingCharacters(in: CharacterSet(charactersIn: ": ")),
                kind: OpenConnectForm.Field.Kind(rawValue: f["type"] as? String ?? "hidden") ?? .hidden,
                value: f["value"] as? String,
                options: (f["options"] as? [[String: Any]] ?? []).map {
                    (name: $0["name"] as? String ?? "", label: $0["label"] as? String ?? $0["name"] as? String ?? "")
                },
                numeric: f["numeric"] as? Bool ?? false)
        }
        return OpenConnectForm(banner: message["banner"] as? String, message: message["message"] as? String,
                               error: message["error"] as? String, fields: fields)
    }
}

/// Writes lines to the login helper from any thread.
private final class LineWriter: @unchecked Sendable {
    private let handle: FileHandle
    private let lock = NSLock()
    init(_ handle: FileHandle) { self.handle = handle }
    func send(_ line: String) {
        lock.withLock { try? handle.write(contentsOf: Data((line + "\n").utf8)) }
    }
}

/// Reads lines from the login helper.
private final class LineReader {
    private let handle: FileHandle
    private var buffer = Data()
    init(_ handle: FileHandle) { self.handle = handle }
    func next() -> String? {
        while true {
            if let index = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<index]
                buffer.removeSubrange(buffer.startIndex...index)
                return String(decoding: line, as: UTF8.self)
            }
            let chunk = handle.availableData
            if chunk.isEmpty { return nil }
            buffer.append(chunk)
        }
    }
}

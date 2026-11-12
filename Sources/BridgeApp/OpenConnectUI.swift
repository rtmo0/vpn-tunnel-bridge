import AppKit
import BridgeClient
import BridgeCore
import WebKit

/// OpenConnect login in the app: server forms, untrusted certificates, and SSO
/// in an embedded web view or the default browser.
final class AppOpenConnectUI: OpenConnectLoginUI {
    private var webLogin: WebLoginWindow?

    func fill(_ form: OpenConnectForm, tunnel: String) -> (values: [String: String], remember: Bool)? {
        DispatchQueue.main.sync { Self.runForm(form, tunnel: tunnel) }
    }

    func trust(tunnel: String, server: String, fingerprint: String, reason: String, details: String?) -> Bool {
        DispatchQueue.main.sync {
            NSApp.activate(ignoringOtherApps: true)
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "The certificate of “\(server)” is not trusted"
            alert.informativeText = "\(reason.prefix(1).uppercased() + reason.dropFirst()).\n\n"
                + "Connect only if your administrator gave you this fingerprint:\n\(fingerprint)"
            alert.addButton(withTitle: "Connect")
            alert.addButton(withTitle: "Cancel")
            let always = NSButton(checkboxWithTitle: "Always trust this certificate for “\(tunnel)”", target: nil, action: nil)
            alert.accessoryView = always
            guard alert.runModal() == .alertFirstButtonReturn else { return false }
            if always.state == .on, let (text, _) = try? TunnelLibrary.load(tunnel),
               var config = try? OpenConnectConfig.parse(text) {
                config.serverCert = fingerprint
                _ = try? TunnelLibrary.updateConfig(config.render(), for: tunnel)
            }
            return true
        }
    }

    func openBrowser(_ url: URL) {
        DispatchQueue.main.async { NSWorkspace.shared.open(url) }
    }

    func startWebLogin(tunnel: String, url: URL, onPage: @escaping @Sendable (OpenConnectWebPage) -> Void,
                       onCancel: @escaping @Sendable () -> Void) {
        DispatchQueue.main.async {
            self.webLogin?.close(cancelled: false)
            let window = WebLoginWindow(title: "Sign in to “\(tunnel)”", url: url, onPage: onPage, onCancel: onCancel)
            self.webLogin = window
            window.show()
        }
    }

    func finishWebLogin() {
        DispatchQueue.main.async {
            self.webLogin?.close(cancelled: false)
            self.webLogin = nil
        }
    }

    // MARK: Forms

    private static func runForm(_ form: OpenConnectForm, tunnel: String) -> (values: [String: String], remember: Bool)? {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Sign in to “\(tunnel)”"
        var info = [form.banner, form.message].compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        if let error = form.error, !error.isEmpty {
            alert.alertStyle = .warning
            info.insert(error, at: 0)
        }
        alert.informativeText = info.joined(separator: "\n\n")
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")

        let grid = NSGridView()
        grid.rowSpacing = 8
        grid.columnSpacing = 8
        var readers: [(String, () -> String)] = []
        var firstEmpty: NSView?
        for field in form.fields where field.isVisible {
            let label = NSTextField(labelWithString: field.label.isEmpty ? field.name : field.label)
            label.alignment = .right
            let control: NSView
            switch field.kind {
            case .select:
                let popup = NSPopUpButton()
                for option in field.options {
                    popup.addItem(withTitle: option.label.isEmpty ? option.name : option.label)
                    popup.lastItem?.representedObject = option.name
                }
                if let value = field.value, let index = field.options.firstIndex(where: { $0.name == value }) {
                    popup.selectItem(at: index)
                }
                readers.append((field.name, { popup.selectedItem?.representedObject as? String ?? "" }))
                control = popup
            default:
                let text: NSTextField = field.kind == .password || field.kind == .token ? NSSecureTextField() : NSTextField()
                text.stringValue = field.value ?? ""
                if field.kind == .token || field.numeric { text.placeholderString = "Code" }
                text.translatesAutoresizingMaskIntoConstraints = false
                text.widthAnchor.constraint(equalToConstant: 240).isActive = true
                if text.stringValue.isEmpty && firstEmpty == nil { firstEmpty = text }
                readers.append((field.name, { text.stringValue }))
                control = text
            }
            grid.addRow(with: [label, control])
        }
        var remember: NSButton?
        if form.fields.contains(where: \.isPassword) {
            let box = NSButton(checkboxWithTitle: "Remember in Keychain", target: nil, action: nil)
            box.state = .on
            grid.addRow(with: [NSGridCell.emptyContentView, box])
            remember = box
        }
        grid.column(at: 0).xPlacement = .trailing
        grid.layoutSubtreeIfNeeded()
        grid.frame.size = grid.fittingSize
        alert.accessoryView = grid
        if let firstEmpty { alert.window.initialFirstResponder = firstEmpty }

        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        var values: [String: String] = [:]
        for (name, read) in readers { values[name] = read() }
        return (values, remember?.state == .on)
    }

    // MARK: Adding a server

    /// Asks for an OpenConnect server and saves it; returns the new tunnel's name.
    static func addServer() -> String? {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Add OpenConnect Server"
        alert.informativeText = "Cisco AnyConnect / ocserv, Fortinet, GlobalProtect, Pulse / Ivanti, F5 or Array. "
            + "Bridge asks for the password, one-time code or SSO sign-in when you connect."
        alert.addButton(withTitle: "Add")
        alert.addButton(withTitle: "Cancel")

        let protocols = NSPopUpButton()
        for p in OpenConnectConfig.VPNProtocol.allCases {
            protocols.addItem(withTitle: p.displayName)
            protocols.lastItem?.representedObject = p.rawValue
        }
        func text(_ placeholder: String) -> NSTextField {
            let f = NSTextField()
            f.placeholderString = placeholder
            f.translatesAutoresizingMaskIntoConstraints = false
            f.widthAnchor.constraint(equalToConstant: 260).isActive = true
            return f
        }
        let server = text("vpn.example.com or vpn.example.com/group")
        let user = text("Optional")
        let group = text("Optional")
        let name = text("Optional")
        let grid = NSGridView(views: [
            [NSTextField(labelWithString: "Type"), protocols],
            [NSTextField(labelWithString: "Server"), server],
            [NSTextField(labelWithString: "Username"), user],
            [NSTextField(labelWithString: "Group"), group],
            [NSTextField(labelWithString: "Name"), name],
        ])
        grid.rowSpacing = 8
        grid.column(at: 0).xPlacement = .trailing
        grid.layoutSubtreeIfNeeded()
        grid.frame.size = grid.fittingSize
        alert.accessoryView = grid
        alert.window.initialFirstResponder = server

        while alert.runModal() == .alertFirstButtonReturn {
            let raw = server.stringValue.trimmingCharacters(in: .whitespaces)
            guard !raw.isEmpty else { continue }
            let kind = (protocols.selectedItem?.representedObject as? String).flatMap(OpenConnectConfig.VPNProtocol.init)
            var config = OpenConnectConfig(vpnProtocol: kind ?? .anyconnect, server: raw)
            let u = user.stringValue.trimmingCharacters(in: .whitespaces)
            let g = group.stringValue.trimmingCharacters(in: .whitespaces)
            config.username = u.isEmpty ? nil : u
            config.group = g.isEmpty ? nil : g
            let n = name.stringValue.trimmingCharacters(in: .whitespaces)
            do {
                return try TunnelLibrary.addOpenConnect(config, name: n.isEmpty ? nil : n).name
            } catch {
                Alerts.show("Could not add the server", error.localizedDescription)
            }
        }
        return nil
    }
}

/// SSO sign-in page (SAML, OIDC) in a small browser window. Every finished page
/// load goes to OpenConnect, which recognises the end of the login.
final class WebLoginWindow: NSObject, WKNavigationDelegate, NSWindowDelegate {
    private let window: NSWindow
    private let webView: WKWebView
    private let onPage: @Sendable (OpenConnectWebPage) -> Void
    private let onCancel: @Sendable () -> Void
    private var lastHeaders: [(name: String, value: String)] = []
    private var closing = false

    init(title: String, url: URL, onPage: @escaping @Sendable (OpenConnectWebPage) -> Void,
         onCancel: @escaping @Sendable () -> Void) {
        self.onPage = onPage
        self.onCancel = onCancel
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()  // keeps the identity provider's "stay signed in"
        webView = WKWebView(frame: NSRect(x: 0, y: 0, width: 520, height: 680), configuration: configuration)
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 680),
                          styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        super.init()
        window.title = title
        window.contentView = webView
        window.delegate = self
        window.isReleasedWhenClosed = false
        window.center()
        webView.navigationDelegate = self
        webView.load(URLRequest(url: url))
    }

    func show() {
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    func close(cancelled: Bool) {
        guard !closing else { return }
        closing = true
        webView.stopLoading()
        window.close()
        if cancelled { onCancel() }
    }

    func windowWillClose(_ notification: Notification) {
        guard !closing else { return }
        closing = true
        onCancel()
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping @MainActor (WKNavigationResponsePolicy) -> Void) {
        // GlobalProtect hands the SAML result over in response headers.
        if navigationResponse.isForMainFrame, let http = navigationResponse.response as? HTTPURLResponse {
            lastHeaders = http.allHeaderFields.compactMap { key, value in
                guard let k = key as? String else { return nil }
                return (name: k, value: "\(value)")
            }
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        report()
    }

    func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) {
        report()
    }

    private func report() {
        guard !closing, let url = webView.url?.absoluteString else { return }
        let headers = lastHeaders
        webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { [onPage] cookies in
            onPage(OpenConnectWebPage(url: url, cookies: cookies.map { (name: $0.name, value: $0.value) },
                                      headers: headers))
        }
    }
}

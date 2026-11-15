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
            alert.messageText = String(localized: "The certificate of “\(server)” is not trusted")
            alert.informativeText = "\(reason.prefix(1).uppercased() + reason.dropFirst()). "
                + String(localized: "Connect only if your administrator gave you this exact fingerprint.")
            // Cancel is the default: pressing Return must not connect to an unknown server.
            alert.addButton(withTitle: String(localized: "Cancel"))
            alert.addButton(withTitle: String(localized: "Connect Anyway"))

            let caption = NSTextField(labelWithString: String(localized: "SERVER FINGERPRINT"))
            caption.font = .systemFont(ofSize: 10, weight: .semibold)
            caption.textColor = .secondaryLabelColor
            let value = NSTextField(wrappingLabelWithString: fingerprint)
            value.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
            value.isSelectable = true
            value.preferredMaxLayoutWidth = 300
            let always = NSButton(checkboxWithTitle: String(localized: "Always trust this certificate for “\(tunnel)”"), target: nil, action: nil)
            let stack = NSStackView(views: [caption, value, always])
            stack.orientation = .vertical
            stack.alignment = .leading
            stack.spacing = 4
            stack.setCustomSpacing(12, after: value)
            stack.layoutSubtreeIfNeeded()
            stack.frame.size = stack.fittingSize
            alert.accessoryView = stack

            guard alert.runModal() == .alertSecondButtonReturn else { return false }
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
            let window = WebLoginWindow(title: String(localized: "Sign in to “\(tunnel)”"), url: url, onPage: onPage, onCancel: onCancel)
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
        let message = [form.banner, form.message].compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: "\n\n")
        let login = LoginForm(title: String(localized: "Sign in to “\(tunnel)”"), message: message.isEmpty ? nil : message,
                              error: form.error, button: String(localized: "Continue"))
        var readers: [(String, () -> String)] = []
        for field in form.fields where field.isVisible {
            let label = field.label.isEmpty ? field.name : field.label
            switch field.kind {
            case .select:
                let popup = login.popup(label, options: field.options.map { ($0.name, $0.label.isEmpty ? $0.name : $0.label) },
                                        selected: field.value)
                readers.append((field.name, { popup.selectedItem?.representedObject as? String ?? "" }))
            default:
                let secure = field.kind == .password || field.kind == .token
                let text = login.field(label, value: field.value ?? "",
                                       placeholder: field.kind == .token || field.numeric ? String(localized: "One-time code") : nil,
                                       secure: secure, required: field.kind != .text || field.isUsername)
                readers.append((field.name, { text.stringValue }))
            }
        }
        let remember = form.fields.contains(where: \.isPassword) ? login.remember() : nil
        guard login.run() else { return nil }
        var values: [String: String] = [:]
        for (name, read) in readers { values[name] = read() }
        return (values, remember?.state == .on)
    }
}

/// SSO sign-in page (SAML, OIDC) in a small browser window. Every finished page
/// load goes to OpenConnect, which recognises the end of the login. The subtitle
/// always shows the domain of the page, so you can see where you type the password.
final class WebLoginWindow: NSObject, WKNavigationDelegate, NSWindowDelegate {
    private let window: NSWindow
    private let webView: WKWebView
    private let progress = NSProgressIndicator()
    private let onPage: @Sendable (OpenConnectWebPage) -> Void
    private let onCancel: @Sendable () -> Void
    private var lastHeaders: [(name: String, value: String)] = []
    private var closing = false
    private var observations: [NSKeyValueObservation] = []

    init(title: String, url: URL, onPage: @escaping @Sendable (OpenConnectWebPage) -> Void,
         onCancel: @escaping @Sendable () -> Void) {
        self.onPage = onPage
        self.onCancel = onCancel
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()  // keeps the identity provider's "stay signed in"
        webView = WKWebView(frame: .zero, configuration: configuration)
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 680),
                          styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        super.init()
        window.title = title
        window.subtitle = url.host ?? ""
        window.delegate = self
        window.isReleasedWhenClosed = false
        window.contentView = makeContent()
        window.center()
        webView.navigationDelegate = self
        observations = [
            webView.observe(\.estimatedProgress, options: [.new]) { [weak self] view, _ in
                DispatchQueue.main.async { self?.updateProgress(view) }
            },
            webView.observe(\.url, options: [.new]) { [weak self] view, _ in
                DispatchQueue.main.async { self?.updateSubtitle(view.url) }
            },
        ]
        webView.load(URLRequest(url: url))
    }

    private func makeContent() -> NSView {
        let content = NSView()
        progress.style = .bar
        progress.isIndeterminate = false
        progress.minValue = 0
        progress.maxValue = 1
        progress.controlSize = .small
        let hint = NSTextField(labelWithString: String(localized: "This window closes itself when the VPN server accepts the sign-in."))
        hint.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        hint.textColor = .secondaryLabelColor
        let footer = NSBox()
        footer.boxType = .separator
        for view in [webView, progress, hint, footer] as [NSView] {
            view.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(view)
        }
        NSLayoutConstraint.activate([
            progress.topAnchor.constraint(equalTo: content.topAnchor),
            progress.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            progress.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            progress.heightAnchor.constraint(equalToConstant: 4),
            webView.topAnchor.constraint(equalTo: content.topAnchor),
            webView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: footer.topAnchor),
            footer.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            footer.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            footer.bottomAnchor.constraint(equalTo: hint.topAnchor, constant: -8),
            hint.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 14),
            hint.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -14),
            hint.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -9),
            content.widthAnchor.constraint(greaterThanOrEqualToConstant: 420),
            content.heightAnchor.constraint(greaterThanOrEqualToConstant: 480),
        ])
        content.addSubview(progress, positioned: .above, relativeTo: webView)
        return content
    }

    private func updateProgress(_ view: WKWebView) {
        progress.doubleValue = view.estimatedProgress
        progress.isHidden = view.estimatedProgress >= 1 || !view.isLoading
    }

    private func updateSubtitle(_ url: URL?) {
        guard let url, let host = url.host else { return }
        window.subtitle = url.scheme == "https" ? host : String(localized: "Not secure — \(host)")
    }

    func show() {
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    func close(cancelled: Bool) {
        guard !closing else { return }
        closing = true
        observations.removeAll()
        webView.stopLoading()
        window.close()
        if cancelled { onCancel() }
    }

    func windowWillClose(_ notification: Notification) {
        guard !closing else { return }
        closing = true
        observations.removeAll()
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

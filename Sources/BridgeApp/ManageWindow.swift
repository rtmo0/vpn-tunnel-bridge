import AppKit
import BridgeClient
import BridgeCore
import SwiftUI

// MARK: - Window

final class ManageSelection: ObservableObject {
    @Published var name: String?
}

/// "Manage Tunnels" window: tunnel list on the left, details and settings on the right.
enum ManageWindow {
    private static var window: NSWindow?
    private static let selection = ManageSelection()

    static func show(model: AppModel, select name: String? = nil) {
        if window == nil {
            let root = ManageView().environmentObject(model).environmentObject(selection)
            let window = NSWindow(contentViewController: NSHostingController(rootView: root))
            window.title = "Tunnels"
            window.styleMask = [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
            // Like Mail or System Settings: the sidebar runs up under the traffic lights,
            // no title bar strip or separator line over the content.
            window.titleVisibility = .hidden
            window.titlebarAppearsTransparent = true
            window.titlebarSeparatorStyle = .none
            window.toolbarStyle = .unified
            window.setContentSize(NSSize(width: 820, height: 580))
            window.minSize = NSSize(width: 680, height: 440)
            window.isReleasedWhenClosed = false
            window.setFrameAutosaveName("BridgeManageWindow")
            if !window.setFrameUsingName("BridgeManageWindow") { window.center() }
            self.window = window
        }
        if let name { selection.name = name }
        if selection.name == nil { selection.name = model.rows.first(where: \.saved)?.name }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
        // A menu bar app isn't always frontmost; make sure the window is visible.
        window?.orderFrontRegardless()
    }
}

struct ManageView: View {
    @EnvironmentObject var model: AppModel
    @EnvironmentObject var selection: ManageSelection

    private var saved: [AppModel.Row] { model.rows.filter(\.saved) }

    var body: some View {
        // A plain HStack instead of NavigationSplitView: hosted in our own window the
        // split view draws a heavy black divider; this gives the native thin one.
        HStack(spacing: 0) {
            sidebar
                .frame(width: 220)
            Divider()
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .ignoresSafeArea(.container, edges: .top)
        .onChange(of: saved.map(\.name)) { _, names in
            if let current = selection.name, !names.contains(current) { selection.name = names.first }
            if selection.name == nil { selection.name = names.first }
        }
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            List(selection: $selection.name) {
                ForEach(saved, id: \.name) { row in
                    TunnelListRow(row: row, busy: model.busy.contains(row.name)).tag(row.name)
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
            .padding(.top, 34)  // room for the window buttons
            Divider()
            HStack(spacing: 2) {
                Button { model.importConfigs() } label: { Image(systemName: "plus").frame(width: 22, height: 20) }
                    .help("Import tunnels from .conf / .ovpn files or files with vless:// links")
                Button {
                    if let name = selection.name { model.remove(name) }
                } label: { Image(systemName: "minus").frame(width: 22, height: 20) }
                    .disabled(selection.name == nil)
                    .help("Remove the selected tunnel")
                Spacer()
                Button { model.openLogs() } label: { Image(systemName: "doc.text.magnifyingglass").frame(width: 22, height: 20) }
                    .help("Open logs")
            }
            .buttonStyle(.borderless)
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
        }
        .background(SidebarMaterial())
    }

    @ViewBuilder private var detail: some View {
        if let name = selection.name, saved.contains(where: { $0.name == name }) {
            TunnelDetail(name: name).id(name)
                .padding(.top, 22)
        } else {
            ContentUnavailableView {
                Label("No Tunnel Selected", systemImage: "shield")
            } description: {
                Text("Import a WireGuard / AmneziaWG .conf or an OpenVPN .ovpn file with +, or paste a vless:// link")
            } actions: {
                Button("Import Tunnels…") { model.importConfigs() }
                Button("Paste VLESS Link") { model.importFromClipboard() }
            }
        }
    }
}

/// The translucent sidebar background used by Finder, Mail and System Settings.
struct SidebarMaterial: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = .sidebar
        view.blendingMode = .behindWindow
        view.state = .followsWindowActiveState
        return view
    }

    func updateNSView(_ view: NSVisualEffectView, context: Context) {}
}

struct TunnelListRow: View {
    let row: AppModel.Row
    let busy: Bool

    private var dot: Color {
        if busy { return .orange }
        guard let status = row.status else { return .clear }
        return status.connected ? .green : .orange
    }

    var body: some View {
        HStack(spacing: 8) {
            Image(nsImage: ProtocolIcon.image(row.kind))
                .renderingMode(.template)
                .foregroundStyle(.secondary)
            Text(row.name).lineLimit(1)
            Spacer()
            Circle().fill(dot).frame(width: 7, height: 7)
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Detail

/// Read-only facts extracted from a config file.
struct ConfigSummary {
    var kind: TunnelKind
    var addresses = ""
    var dns = ""
    var servers = ""
    var routes = ""
    var mtu = ""
    var parameters: [(name: String, value: String)] = []
    var login = ""
    var needsLogin = false
    var warnings: [String] = []

    init(text: String, kind: TunnelKind) {
        self.kind = kind
        switch kind {
        case .amneziawg, .wireguard:
            guard let c = try? TunnelConfig.parse(text) else { return }
            addresses = c.addresses.map(\.description).joined(separator: ", ")
            dns = (c.dnsServers.map(\.description) + c.dnsSearchDomains).joined(separator: ", ")
            servers = c.peers.compactMap { $0.endpoint?.description }.joined(separator: ", ")
            routes = c.peers.flatMap(\.allowedIPs).map(\.description).joined(separator: ", ")
            mtu = c.mtu.map(String.init) ?? "Automatic"
            parameters = c.deviceParameters.map { p in
                (p.name, p.isSecret ? "••••••••" : (p.value.count > 28 ? "\(p.value.prefix(24))…" : p.value))
            }
            warnings = c.warnings
        case .openvpn:
            guard let c = try? OpenVPNConfig.parse(text) else { return }
            servers = c.remotes.joined(separator: ", ")
            routes = c.redirectsGateway ? "All traffic (redirect-gateway)" : "Pushed by the server"
            needsLogin = c.needsUsernamePassword
            var login: [String] = []
            login.append(c.needsUsernamePassword ? "Username and password" : "Certificate")
            if c.staticChallenge != nil { login.append("one-time code") }
            if c.hasEncryptedPrivateKey { login.append("key passphrase") }
            self.login = login.joined(separator: " + ")
        case .vless:
            guard let c = try? VLESSConfig.parse(text) else { return }
            servers = c.endpoint
            dns = VLESSConfig.defaultDNS.joined(separator: ", ") + " (Bridge default)"
            routes = "All traffic (IPv6 when the server supports it)"
            var p: [(String, String)] = [("Transport", c.transport.rawValue), ("Security", c.security.rawValue)]
            if let flow = c.flow { p.append(("Flow", flow)) }
            if c.encryption != "none" { p.append(("Encryption", "\(c.encryption.prefix(24))…")) }
            if let sni = c.serverName { p.append(("SNI", sni)) }
            if c.security != .none { p.append(("Fingerprint", c.fingerprint ?? "chrome")) }
            if !c.alpn.isEmpty { p.append(("ALPN", c.alpn.joined(separator: ","))) }
            if c.pinnedPeerCertSha256 != nil { p.append(("Pinned certificate", "yes")) }
            if let sid = c.realityShortID { p.append(("Short ID", sid)) }
            if let spx = c.realitySpiderX { p.append(("SpiderX", spx)) }
            if let host = c.hostHeader { p.append(("Host", host)) }
            if let path = c.path { p.append(("Path", path)) }
            if let service = c.serviceName { p.append(("Service name", service)) }
            if let mode = c.mode { p.append(("Mode", mode)) }
            if c.extra != nil { p.append(("Extra", "custom")) }
            parameters = p.map { (name: $0.0, value: $0.1) }
        }
    }
}

struct TunnelDetail: View {
    let name: String
    @EnvironmentObject var model: AppModel

    @State private var summary: ConfigSummary?
    @State private var configText = ""
    @State private var saved = TunnelSettings()
    @State private var settings = TunnelSettings()
    @State private var networksText = ""
    @State private var dnsText = ""
    @State private var domainsText = ""
    @State private var username = ""
    @State private var password = ""
    @State private var hasSavedLogin = false
    @State private var error: String?
    @State private var editing = false
    @State private var renaming = false
    @State private var newName = ""
    @State private var loginSaved = false

    private var row: AppModel.Row? { model.rows.first { $0.name == name } }
    private var busy: Bool { model.busy.contains(name) }

    private var draft: TunnelSettings {
        var s = settings
        s.networks = Self.split(networksText)
        s.dnsServers = Self.split(dnsText)
        s.splitDNSDomains = Self.split(domainsText)
        if s.routing == .config || s.routing == .allTraffic { s.networks = [] }
        if s.dnsMode != .custom { s.dnsServers = [] }
        return s
    }

    private var dirty: Bool { draft != saved }

    var body: some View {
        VStack(spacing: 0) {
            header
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
            Divider()
            form
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if dirty {
                    Button("Revert") { load() }
                    Button("Save") { save() }
                        .keyboardShortcut("s", modifiers: .command)
                        .buttonStyle(.borderedProminent)
                }
            }
        }
        .sheet(isPresented: $editing) {
            ConfigEditor(name: name, text: configText) { load() }
        }
        .alert("Rename Tunnel", isPresented: $renaming) {
            TextField("Name", text: $newName)
            Button("Rename") { rename() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Letters, digits, “-”, “_” and “.”")
        }
        .onAppear(perform: load)
    }

    private var form: some View {
        Form {
            if let status = row?.status { statusSection(status) }
            configurationSection
            if summary?.needsLogin == true { loginSection }
            routingSection
            dnsSection
            if let error {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: Sections

    private var header: some View {
            HStack(spacing: 12) {
                Image(nsImage: ProtocolIcon.image(summary?.kind ?? row?.kind ?? .wireguard))
                    .renderingMode(.template)
                    .resizable()
                    .frame(width: 40, height: 23)
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(name).font(.title3.weight(.semibold))
                    Text(stateText).font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Menu {
                    Button("Rename…") {
                        newName = name
                        renaming = true
                    }
                    .disabled(row?.status != nil)
                    Button("Edit Configuration…") { editing = true }
                    Button("Show in Finder") { model.reveal(name) }
                    Divider()
                    Button("Remove…", role: .destructive) { model.remove(name) }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                if busy {
                    ProgressView().controlSize(.small)
                } else {
                    Toggle("", isOn: Binding(get: { row?.status != nil }, set: { _ in model.toggle(name) }))
                        .toggleStyle(.switch)
                        .labelsHidden()
                        .disabled(!model.helperReady)
                }
            }
    }

    private var stateText: String {
        let kind = (summary?.kind ?? row?.kind)?.displayName ?? ""
        if busy { return "\(kind) · \(row?.status == nil ? "Connecting…" : "Disconnecting…")" }
        guard let status = row?.status else { return "\(kind) · Disconnected" }
        return "\(kind) · \(status.state)"
    }

    private func statusSection(_ status: TunnelStatus) -> some View {
        Section("Status") {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                LabeledContent("Connected for", value: uptime(status.startedAt, now: context.date))
            }
            if let server = status.server { LabeledContent("Server", value: server) }
            if !status.interface.isEmpty { LabeledContent("Interface", value: status.interface) }
            if !status.addresses.isEmpty { LabeledContent("Addresses", value: status.addresses.joined(separator: ", ")) }
            if !status.dnsServers.isEmpty { LabeledContent("DNS", value: status.dnsServers.joined(separator: ", ")) }
            if status.kind != .openvpn {
                LabeledContent(status.kind == .vless ? "Last check" : "Last handshake",
                               value: status.lastHandshake.map { ago($0) } ?? "Never")
            }
            LabeledContent("Traffic", value: "↓ \(bytes(status.rxBytes))   ↑ \(bytes(status.txBytes))")
            ForEach(status.warnings, id: \.self) { warning in
                Label(warning, systemImage: "info.circle").font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private var configurationSection: some View {
        Section {
            if let s = summary {
                if !s.servers.isEmpty { LabeledContent("Server", value: s.servers) }
                if !s.addresses.isEmpty { LabeledContent("Addresses", value: s.addresses) }
                if !s.dns.isEmpty { LabeledContent("DNS", value: s.dns) }
                if !s.routes.isEmpty { LabeledContent("Routes", value: s.routes) }
                if s.kind != .openvpn && s.kind != .vless { LabeledContent("MTU", value: s.mtu) }
                if !s.parameters.isEmpty {
                    DisclosureGroup(s.kind == .vless ? "VLESS settings (\(s.parameters.count))"
                                    : "AmneziaWG parameters (\(s.parameters.count))") {
                        ForEach(s.parameters, id: \.name) { p in
                            LabeledContent(p.name) { Text(p.value).font(.callout.monospaced()) }
                        }
                    }
                }
                if s.kind == .openvpn { LabeledContent("Authentication", value: s.login) }
            }
        } header: {
            HStack {
                Text("Configuration")
                Spacer()
                Button("Edit…") { editing = true }
                    .buttonStyle(.link)
                    .font(.callout)
            }
        }
    }

    private var loginSection: some View {
        Section {
            TextField("Username", text: $username)
            SecureField("Password", text: $password,
                        prompt: Text(hasSavedLogin ? "Saved in Keychain — type to replace" : "Password"))
            HStack {
                if hasSavedLogin {
                    Button("Forget") {
                        Keychain.deleteCredentials(for: name)
                        username = ""
                        password = ""
                        hasSavedLogin = false
                    }
                }
                Spacer()
                if loginSaved { Text("Saved").foregroundStyle(.secondary).font(.callout) }
                Button("Save to Keychain") {
                    do {
                        try Keychain.saveCredentials(username: username, password: password, for: name)
                        hasSavedLogin = true
                        loginSaved = true
                    } catch { self.error = "\(error)" }
                }
                .disabled(username.isEmpty || password.isEmpty)
            }
        } header: {
            Text("Sign-in")
        } footer: {
            Text("Stored in your login keychain. Leave empty to be asked when connecting.")
                .font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var routingSection: some View {
        Section {
            Picker("Send through VPN", selection: $settings.routing) {
                Text("As in configuration").tag(TunnelSettings.Routing.config)
                Text("All traffic").tag(TunnelSettings.Routing.allTraffic)
                Text("Only these networks").tag(TunnelSettings.Routing.onlyListed)
                Text("All traffic except these networks").tag(TunnelSettings.Routing.allExceptListed)
            }
            if settings.routing == .onlyListed || settings.routing == .allExceptListed {
                TextField("Networks", text: $networksText, prompt: Text("10.0.0.0/8, 192.168.50.0/24, 203.0.113.7"),
                          axis: .vertical)
                    .lineLimit(2...6)
                    .font(.body.monospaced())
            }
            Toggle("Keep local networks off the VPN", isOn: $settings.excludeLocalNetworks)
            Toggle("Kill switch", isOn: $settings.killSwitch)
        } header: {
            Text("Routing")
        } footer: {
            Text(routingFooter).font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var routingFooter: String {
        let base: String
        switch settings.routing {
        case .config:
            switch summary?.kind {
            case .openvpn: base = "Uses the routes the OpenVPN server pushes."
            case .vless: base = "All traffic. IPv6 goes through the tunnel when the server can reach IPv6, otherwise it is blocked."
            default: base = "Uses AllowedIPs from the configuration."
            }
        case .allTraffic: base = "Everything goes through the tunnel."
        case .onlyListed: base = "Split tunnelling: only these networks use the VPN, everything else goes direct."
        case .allExceptListed: base = "These networks go direct, everything else uses the VPN."
        }
        guard settings.killSwitch else { return base }
        return base + " Kill switch: while connected, only the VPN, its server and your local network are reachable; "
            + "if the tunnel drops, traffic stays blocked until you reconnect or unblock it from the menu."
    }

    private var dnsSection: some View {
        Section {
            Picker("DNS servers", selection: $settings.dnsMode) {
                Text("From configuration").tag(TunnelSettings.DNSMode.config)
                Text("Custom").tag(TunnelSettings.DNSMode.custom)
                Text("Don't change system DNS").tag(TunnelSettings.DNSMode.system)
            }
            if settings.dnsMode == .custom {
                TextField("Servers", text: $dnsText, prompt: Text("1.1.1.1, 9.9.9.9"))
                    .font(.body.monospaced())
            }
            if settings.dnsMode != .system {
                TextField("Only for domains", text: $domainsText, prompt: Text("corp.example, internal.lan"))
                    .font(.body.monospaced())
            }
        } header: {
            Text("DNS")
        } footer: {
            Text("“Only for domains” is split DNS: the VPN's DNS answers just these domains, the rest uses your normal DNS.")
                .font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: Actions

    private func load() {
        error = nil
        guard let loaded = try? TunnelLibrary.load(name) else { return }
        configText = loaded.text
        summary = ConfigSummary(text: loaded.text, kind: loaded.kind)
        saved = TunnelLibrary.settings(for: name)
        settings = saved
        networksText = saved.networks.joined(separator: ", ")
        dnsText = saved.dnsServers.joined(separator: ", ")
        domainsText = saved.splitDNSDomains.joined(separator: ", ")
        // Never read the password here: that would show a Keychain prompt every time
        // the window opens. Only connecting needs it.
        hasSavedLogin = Keychain.hasCredentials(for: name)
        username = Keychain.savedUsername(for: name) ?? ""
        password = ""
    }

    private func save() {
        let next = draft
        do {
            try TunnelLibrary.saveSettings(next, for: name)
        } catch {
            self.error = "\(error)"
            return
        }
        error = nil
        saved = next
        settings = next
        if model.isActive(name),
           Alerts.confirm("Reconnect “\(name)”?", "New settings apply after reconnecting.", button: "Reconnect") {
            model.reconnect(name)
        }
    }

    private func rename() {
        let target = TunnelName.sanitized(newName)
        guard target != name else { return }
        do {
            _ = try TunnelLibrary.rename(name, to: target)
            model.refresh()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { ManageWindow.show(model: model, select: target) }
        } catch {
            self.error = "\(error)"
        }
    }

    // MARK: Formatting

    static func split(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " || $0 == ";" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private func uptime(_ since: Date, now: Date) -> String {
        let s = max(0, Int(now.timeIntervalSince(since)))
        return s >= 3600 ? String(format: "%d:%02d:%02d", s / 3600, s % 3600 / 60, s % 60)
            : String(format: "%02d:%02d", s / 60, s % 60)
    }

    private func ago(_ date: Date) -> String {
        let s = max(0, Int(Date().timeIntervalSince(date)))
        return s < 60 ? "\(s) s ago" : "\(s / 60) min ago"
    }

    private func bytes(_ count: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .binary)
    }
}

// MARK: - Config editor

struct ConfigEditor: View {
    let name: String
    @State var text: String
    let onSave: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var error: String?

    init(name: String, text: String, onSave: @escaping () -> Void) {
        self.name = name
        _text = State(initialValue: text)
        self.onSave = onSave
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Edit “\(name)”").font(.headline)
            TextEditor(text: $text)
                .font(.system(size: 12, design: .monospaced))
                .autocorrectionDisabled()
                .scrollContentBackground(.hidden)
                .padding(6)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.secondary.opacity(0.25)))
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.callout)
                    .textSelection(.enabled)
            }
            HStack {
                Text("Changes apply the next time you connect.").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    do {
                        _ = try TunnelLibrary.updateConfig(text, for: name)
                        onSave()
                        dismiss()
                    } catch {
                        self.error = "\(error)"
                    }
                }
                .keyboardShortcut("s", modifiers: .command)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(16)
        .frame(minWidth: 640, minHeight: 460)
    }
}

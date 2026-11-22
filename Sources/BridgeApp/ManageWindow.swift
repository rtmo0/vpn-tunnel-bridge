import AppKit
import BridgeClient
import BridgeCore
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Window

final class ManageSelection: ObservableObject {
    @Published var name: String?
    /// The Add Tunnel sheet is open.
    @Published var adding = false
}

/// "Manage Tunnels" window: tunnel list on the left, details and settings on the right.
enum ManageWindow {
    private static var window: NSWindow?
    private static var closeObserver: NSObjectProtocol?
    private static let selection = ManageSelection()

    static func show(model: AppModel, select name: String? = nil, addTunnel: Bool = false) {
        if window == nil {
            let root = ManageView().environmentObject(model).environmentObject(selection)
            let window = NSWindow(contentViewController: NSHostingController(rootView: root))
            window.title = String(localized: "Tunnels")
            window.styleMask = [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
            // Like Mail or System Settings: the sidebar runs up under the traffic lights,
            // no title bar strip or separator line over the content.
            window.titleVisibility = .hidden
            window.titlebarAppearsTransparent = true
            window.titlebarSeparatorStyle = .none
            window.toolbarStyle = .unified
            window.setContentSize(NSSize(width: 860, height: 620))
            window.minSize = NSSize(width: 700, height: 480)
            window.isReleasedWhenClosed = false
            window.setFrameAutosaveName("BridgeManageWindow")
            if !window.setFrameUsingName("BridgeManageWindow") { window.center() }
            // Drop the window when it closes: a hidden SwiftUI view kept alive keeps tracking
            // the model, and its observation records pile up with every refresh.
            closeObserver = NotificationCenter.default.addObserver(
                forName: NSWindow.willCloseNotification, object: window, queue: .main
            ) { _ in
                if let observer = closeObserver { NotificationCenter.default.removeObserver(observer) }
                closeObserver = nil
                self.window = nil
            }
            self.window = window
        }
        if let name { selection.name = name }
        if selection.name == nil { selection.name = model.rows.first(where: \.saved)?.name }
        if addTunnel { selection.adding = true }
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
    @State private var dropTargeted = false

    var body: some View {
        // A plain HStack instead of NavigationSplitView: hosted in our own window the
        // split view draws a heavy black divider; this gives the native thin one.
        HStack(spacing: 0) {
            sidebar
                .frame(width: 240)
            Divider()
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .ignoresSafeArea(.container, edges: .top)
        .overlay {
            if dropTargeted {
                RoundedRectangle(cornerRadius: 10).strokeBorder(Color.accentColor, lineWidth: 3)
                    .ignoresSafeArea()
                    .allowsHitTesting(false)
            }
        }
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
            importDropped(providers)
            return true
        }
        .sheet(isPresented: $selection.adding) {
            AddTunnelSheet { name in
                selection.adding = false
                if let name { selection.name = name }
            }
            .environmentObject(model)
        }
        .onChange(of: saved.map(\.name)) { _, names in
            if let current = selection.name, !names.contains(current) { selection.name = names.first }
            if selection.name == nil { selection.name = names.first }
        }
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            if saved.isEmpty {
                Text("No tunnels")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.top, 58)
                Spacer()
            } else {
                List(selection: $selection.name) {
                    ForEach(saved, id: \.name) { row in
                        TunnelListRow(row: row, phase: model.phase(of: row)).tag(row.name)
                    }
                }
                .listStyle(.sidebar)
                .scrollContentBackground(.hidden)
                .padding(.top, 34)  // room for the window buttons
            }
            Divider()
            HStack(spacing: 2) {
                Button { selection.adding = true } label: { Image(systemName: "plus").frame(width: 22, height: 20) }
                    .help("Add a tunnel")
                Button {
                    if let name = selection.name { model.remove(name) }
                } label: { Image(systemName: "minus").frame(width: 22, height: 20) }
                    .disabled(selection.name == nil)
                    .help("Remove the selected tunnel")
                Spacer()
                Text("Bridge \(Updater.currentVersion)")
                    .font(.caption)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
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
                Label(saved.isEmpty ? String(localized: "No Tunnels Yet") : String(localized: "No Tunnel Selected"), systemImage: "shield")
            } description: {
                Text("Add a configuration file, a share link or a corporate VPN server.")
            } actions: {
                Button("Add Tunnel…") { selection.adding = true }
                    .buttonStyle(.borderedProminent)
                Text("or drop a .conf or .ovpn file on this window")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func importDropped(_ providers: [NSItemProvider]) {
        final class Collected: @unchecked Sendable {
            let lock = NSLock()
            var urls: [URL] = []
        }
        let collected = Collected()
        let group = DispatchGroup()
        for provider in providers {
            group.enter()
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                if let url { collected.lock.withLock { collected.urls.append(url) } }
                group.leave()
            }
        }
        group.notify(queue: .main) {
            let urls = collected.lock.withLock { collected.urls }
            guard !urls.isEmpty else { return }
            let result = model.importFiles(urls)
            if let first = result.names.first { selection.name = first }
            if !result.errors.isEmpty {
                Alerts.show(result.names.isEmpty ? String(localized: "Could not import") : String(localized: "Some files were not imported"),
                            result.errors.joined(separator: "\n"))
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
    let phase: TunnelPhase

    var body: some View {
        HStack(spacing: 9) {
            KindTile(kind: row.brand, size: 20, shadow: false)
            VStack(alignment: .leading, spacing: 1) {
                Text(row.name).lineLimit(1)
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    Text(subtitle(now: context.date))
                        .font(.caption)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 4)
            if let color = phase.color {
                Circle().fill(color).frame(width: 7, height: 7)
            }
        }
        .padding(.vertical, 3)
    }

    private func subtitle(now: Date) -> String {
        guard phase == .connected, let status = row.status else { return phase.title }
        return String(localized: "Connected · \(Format.uptime(since: status.startedAt, now: now))")
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
            mtu = c.mtu.map(String.init) ?? String(localized: "Automatic")
            parameters = c.deviceParameters.map { p in
                (p.name, p.isSecret ? "••••••••" : (p.value.count > 28 ? "\(p.value.prefix(24))…" : p.value))
            }
            warnings = c.warnings
        case .openvpn:
            guard let c = try? OpenVPNConfig.parse(text) else { return }
            servers = c.remotes.joined(separator: ", ")
            routes = c.redirectsGateway ? String(localized: "All traffic (redirect-gateway)") : String(localized: "Pushed by the server")
            needsLogin = c.needsUsernamePassword
            var login: [String] = []
            login.append(c.needsUsernamePassword ? String(localized: "Username and password") : String(localized: "Certificate"))
            if c.staticChallenge != nil { login.append(String(localized: "one-time code")) }
            if c.hasEncryptedPrivateKey { login.append(String(localized: "key passphrase")) }
            self.login = login.joined(separator: " + ")
        case .openconnect:
            guard let c = try? OpenConnectConfig.parse(text) else { return }
            servers = c.url
            routes = String(localized: "Pushed by the server")
            dns = String(localized: "Pushed by the server")
            needsLogin = true
            var p: [(name: String, value: String)] = [("Type", c.vpnProtocol.displayName)]
            if let user = c.username { p.append(("Username", user)) }
            if let group = c.group { p.append(("Group", group)) }
            if c.serverCert != nil { p.append(("Pinned certificate", "yes")) }
            if c.certificate != nil { p.append(("Client certificate", "embedded")) }
            if c.disableDTLS { p.append(("DTLS", "off")) }
            parameters = p
            login = String(localized: "Asked when connecting (forms, one-time codes, SSO)")
        case .vless, .trojan, .hysteria2:
            guard let link = try? ProxyLink.parse(text) else { return }
            servers = link.endpoint
            dns = ProxyLink.defaultDNS.joined(separator: ", ") + String(localized: " (Bridge default)")
            routes = String(localized: "All traffic (IPv6 when the server supports it)")
            parameters = link.summary
        }
    }
}


/// Details and settings of one tunnel. Settings are saved as soon as they change (text
/// fields when you leave them); a connected tunnel then offers to reconnect.
struct TunnelDetail: View {
    let name: String
    @EnvironmentObject var model: AppModel

    private enum Field: Hashable { case networks, dns, domains, username, password }

    @State private var summary: ConfigSummary?
    @State private var configText = ""
    @State private var saved = TunnelSettings()
    @State private var settings = TunnelSettings()
    @State private var loaded = false
    @State private var networksText = ""
    @State private var dnsText = ""
    @State private var domainsText = ""
    @State private var networksError: String?
    @State private var dnsError: String?
    @State private var domainsError: String?
    @State private var username = ""
    @State private var password = ""
    @State private var hasSavedLogin = false
    @State private var loginSaved = false
    @State private var error: String?
    @State private var editing = false
    @State private var renaming = false
    @State private var newName = ""
    @State private var killSwitchInfo = false
    @FocusState private var focus: Field?

    private var row: AppModel.Row? { model.rows.first { $0.name == name } }
    private var busy: Bool { model.busy.contains(name) }

    private var draft: TunnelSettings {
        var s = settings
        s.networks = Self.split(networksText)
        s.dnsServers = Self.split(dnsText)
        s.splitDNSDomains = Self.split(domainsText)
        if s.routing == .config || s.routing == .allTraffic { s.networks = [] }
        if s.dnsMode != .custom { s.dnsServers = [] }
        if s.dnsMode == .system { s.splitDNSDomains = [] }
        return s
    }

    var body: some View {
        VStack(spacing: 0) {
            header
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
            Divider()
            form
        }
        .sheet(isPresented: $editing) {
            ConfigEditor(name: name, kind: summary?.kind ?? row?.kind ?? .wireguard,
                         brand: row?.brand ?? .wireguard, text: configText) { load() }
        }
        .alert("Rename Tunnel", isPresented: $renaming) {
            TextField("Name", text: $newName)
            Button("Rename") { rename() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Letters, digits, “-”, “_” and “.”")
        }
        .onAppear(perform: load)
        .onDisappear {
            commit()
            saveLogin()
        }
        .onChange(of: settings) { _, _ in commit() }
        .onChange(of: focus) { old, _ in
            switch old {
            case .username?, .password?: saveLogin()
            case .some: commit()
            case nil: break
            }
        }
    }

    private var form: some View {
        Form {
            if model.needsReconnect(name) { reconnectBanner }
            if let status = row?.status { statusSection(status) }
            configurationSection
            if summary?.needsLogin == true { loginSection }
            if summary?.kind.usesXray == true { modeSection }
            if settings.isLocalProxy {
                Section("Routing") { profilePicker }
            } else {
                routingSection
                dnsSection
            }
            if let error {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: Sections

    private var header: some View {
        HStack(spacing: 12) {
            KindTile(kind: row?.brand ?? AddTunnelKind(summary?.kind ?? .wireguard), size: 32)
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
            .help(row?.status != nil ? String(localized: "Disconnect to rename the tunnel") : String(localized: "More actions"))
            if busy {
                ProgressView().controlSize(.small)
            } else {
                Toggle("", isOn: Binding(get: { row?.status != nil }, set: { _ in model.toggle(name) }))
                    .toggleStyle(.switch)
                    .labelsHidden()
            }
        }
    }

    private var stateText: String {
        let kind = (summary?.kind ?? row?.kind)?.displayName ?? ""
        let phase = row.map(model.phase(of:)) ?? .off
        return "\(kind) · \(phase.title)"
    }

    private var reconnectBanner: some View {
        Section {
            HStack(spacing: 10) {
                Image(systemName: "arrow.clockwise.circle.fill")
                    .foregroundStyle(.tint)
                    .font(.title3)
                Text("Settings changed — reconnect “\(name)” to apply them.")
                Spacer()
                Button("Reconnect") { model.reconnect(name) }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    private func statusSection(_ status: TunnelStatus) -> some View {
        Section("Status") {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                LabeledContent("Connected for", value: Format.uptime(since: status.startedAt, now: context.date))
                    .monospacedDigit()
            }
            if let rate = model.rates[name] {
                LabeledContent("Speed", value: "↓ \(Format.rate(rate.rx)) · ↑ \(Format.rate(rate.tx))")
                    .monospacedDigit()
            }
            LabeledContent("Total", value: "↓ \(Format.bytes(status.rxBytes)) · ↑ \(Format.bytes(status.txBytes))")
                .monospacedDigit()
            if !status.addresses.isEmpty {
                LabeledContent(status.addresses.count == 1 ? String(localized: "Address") : String(localized: "Addresses"),
                               value: status.addresses.joined(separator: ", "))
                    .textSelection(.enabled)
            }
            if status.kind != .openvpn && status.kind != .openconnect {
                // "… ago" has to tick on its own: the model only publishes real changes.
                TimelineView(.periodic(from: .now, by: 1)) { _ in
                    LabeledContent(status.kind.usesXray ? String(localized: "Last check") : String(localized: "Last handshake"),
                                   value: status.lastHandshake.map { Format.ago($0) } ?? String(localized: "Never"))
                }
            }
            ForEach(status.warnings, id: \.self) { warning in
                Label(warning, systemImage: "info.circle").font(.callout).foregroundStyle(.secondary)
            }
            if let sites = status.directSites, !sites.isEmpty {
                DisclosureGroup {
                    DirectSitesStatusList(sites: sites)
                } label: {
                    LabeledContent("Direct sites", value: String(localized:
                        "\(sites.count) site(s), \(sites.reduce(0) { $0 + $1.addresses }) address(es)"))
                }
            }
        }
    }

    private var configurationSection: some View {
        Section {
            if let s = summary {
                if !s.servers.isEmpty { LabeledContent("Server", value: s.servers).textSelection(.enabled) }
                if !s.addresses.isEmpty { LabeledContent(String(localized: "Addresses"), value: s.addresses) }
                if !s.dns.isEmpty { LabeledContent("DNS", value: s.dns) }
                if !s.routes.isEmpty { LabeledContent("Routes", value: s.routes) }
                if s.kind != .openvpn && s.kind != .openconnect && !s.kind.usesXray { LabeledContent("MTU", value: s.mtu) }
                if !s.parameters.isEmpty {
                    DisclosureGroup(s.kind.usesXray || s.kind == .openconnect ? String(localized: "\(s.kind.displayName) settings (\(s.parameters.count))")
                                    : String(localized: "\(s.kind.displayName) parameters (\(s.parameters.count))")) {
                        ForEach(s.parameters, id: \.name) { p in
                            LabeledContent(p.name) { Text(p.value).font(.callout.monospaced()) }
                        }
                    }
                }
                if s.kind == .openvpn || s.kind == .openconnect { LabeledContent("Authentication", value: s.login) }
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
                .focused($focus, equals: .username)
                .onSubmit(saveLogin)
            SecureField("Password", text: $password,
                        prompt: Text(hasSavedLogin ? String(localized: "Saved in Keychain") : String(localized: "Asked when connecting")))
                .focused($focus, equals: .password)
                .onSubmit(saveLogin)
            if hasSavedLogin {
                HStack {
                    Text(loginSaved ? String(localized: "Saved to your login keychain.") : String(localized: "Stored in your login keychain."))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Forget Password…") { forgetLogin() }
                        .buttonStyle(.link)
                }
            }
        } header: {
            Text("Sign-in")
        } footer: {
            Text("Type a password to save it. Leave it empty to be asked when connecting.")
                .font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var routingSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 4) {
                Picker("Send through VPN", selection: $settings.routing) {
                    Text("As in configuration").tag(TunnelSettings.Routing.config)
                    Text("All traffic").tag(TunnelSettings.Routing.allTraffic)
                    Text("Only these networks").tag(TunnelSettings.Routing.onlyListed)
                    Text("All traffic except these networks").tag(TunnelSettings.Routing.allExceptListed)
                }
                Text(routingHint).font(.caption).foregroundStyle(.secondary)
            }
            if settings.routing == .onlyListed || settings.routing == .allExceptListed {
                listField(settings.routing == .allExceptListed ? "Networks and sites" : "Networks",
                          text: $networksText,
                          prompt: settings.routing == .allExceptListed ? "192.168.50.0/24, 203.0.113.7, example.com"
                              : "10.0.0.0/8, 192.168.50.0/24, 203.0.113.7",
                          field: .networks, error: networksError)
            }
            Toggle("Keep local networks off the VPN", isOn: $settings.excludeLocalNetworks)
            Toggle(isOn: $settings.killSwitch) {
                HStack(spacing: 4) {
                    Text("Kill switch")
                    Button { killSwitchInfo = true } label: { Image(systemName: "info.circle") }
                        .buttonStyle(.borderless)
                        .foregroundStyle(.secondary)
                        .help("About the kill switch")
                        .popover(isPresented: $killSwitchInfo, arrowEdge: .bottom) {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Kill switch").font(.headline)
                                Text("While connected, only the VPN, its server and your local network are reachable. If the tunnel drops, traffic stays blocked until you reconnect or choose Unblock Internet in the menu.")
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            .padding(14)
                            .frame(width: 300)
                        }
                }
            }
            if summary?.kind.usesXray == true { profilePicker }
        } header: {
            Text("Routing")
        }
    }

    private var modeSection: some View {
        Section {
            Picker("Connect as", selection: Binding(
                get: { settings.isLocalProxy },
                set: { settings.proxyPort = $0 ? (settings.proxyPort ?? TunnelSettings.defaultProxyPort) : nil })) {
                Text("System-wide VPN").tag(false)
                Text("Local proxy").tag(true)
            }
            if settings.isLocalProxy {
                TextField("Proxy port", value: Binding(
                    get: { settings.proxyPort ?? TunnelSettings.defaultProxyPort },
                    set: { settings.proxyPort = $0 }), format: .number.grouping(.never))
                    .font(.body.monospaced())
            }
        } header: {
            Text("Mode")
        } footer: {
            Group {
                if settings.isLocalProxy {
                    Text("Runs without the network helper or administrator rights. Only apps set to the SOCKS5 or HTTP proxy 127.0.0.1:\(settings.proxyPort ?? TunnelSettings.defaultProxyPort) use it.")
                } else {
                    Text("All apps go through the VPN. Uses the network helper.")
                }
            }
            .font(.caption).foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var profilePicker: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Picker("Routing profile", selection: $settings.routingProfile) {
                    Text("None").tag(String?.none)
                    ForEach(model.routingProfiles, id: \.self) { Text($0).tag(Optional($0)) }
                }
            }
            HStack(spacing: 4) {
                Text("Decides per site what goes through the VPN, direct or blocked.")
                Button("Manage Profiles…") { SettingsWindow.show(model: model, tab: .profiles) }
                    .buttonStyle(.link)
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    private var routingHint: String {
        switch settings.routing {
        case .config:
            switch summary?.kind {
            case .openvpn, .openconnect: String(localized: "Uses the routes the server pushes.")
            case .vless, .trojan, .hysteria2: String(localized: "All traffic; IPv6 too when the server can reach it.")
            default: String(localized: "Uses AllowedIPs from the configuration.")
            }
        case .allTraffic: String(localized: "Everything goes through the VPN.")
        case .onlyListed: String(localized: "Only these networks use the VPN; everything else goes direct.")
        case .allExceptListed: String(localized: "These networks and sites go direct; everything else uses the VPN.")
        }
    }

    @ViewBuilder private var dnsSection: some View {
        if settings.routingProfile != nil {
            Section("DNS") {
                LabeledContent("DNS servers", value: "Answered by the routing profile")
            }
            .foregroundStyle(.secondary)
        } else {
            Section {
                Picker("DNS servers", selection: $settings.dnsMode) {
                    Text("From configuration").tag(TunnelSettings.DNSMode.config)
                    Text("Custom").tag(TunnelSettings.DNSMode.custom)
                    Text("Don't change system DNS").tag(TunnelSettings.DNSMode.system)
                }
                if settings.dnsMode == .custom {
                    listField("Servers", text: $dnsText, prompt: "1.1.1.1, 9.9.9.9", field: .dns, error: dnsError)
                }
                if settings.dnsMode != .system {
                    listField("Only for domains", text: $domainsText, prompt: "corp.example, internal.lan",
                              field: .domains, error: domainsError)
                }
            } header: {
                Text("DNS")
            } footer: {
                Text("With “Only for domains”, just these domains use the VPN's DNS.")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    /// A comma-separated list: the label on its own line, the whole list below it,
    /// left-aligned and wrapping, so long lists stay readable.
    private func listField(_ title: LocalizedStringKey, text: Binding<String>, prompt: String,
                           field: Field, error: String?) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
            TextField(title, text: text, prompt: Text(prompt), axis: .vertical)
                .labelsHidden()
                .textFieldStyle(.roundedBorder)
                .multilineTextAlignment(.leading)
                .lineLimit(1...6)
                .font(.callout.monospaced())
                .focused($focus, equals: field)
                .onSubmit(commit)
            fieldError(error)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder private func fieldError(_ message: String?) -> some View {
        if let message {
            Label("\(message). Not saved.", systemImage: "exclamationmark.circle.fill")
                .font(.caption)
                .foregroundStyle(.red)
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
        networksError = nil
        dnsError = nil
        domainsError = nil
        // Never read the password here: that would show a Keychain prompt every time
        // the window opens. Only connecting needs it.
        hasSavedLogin = Keychain.hasCredentials(for: name)
        username = Keychain.savedUsername(for: name) ?? ""
        password = ""
        self.loaded = true
    }

    /// Validates the draft and saves it; an invalid field is marked and nothing is saved.
    private func commit() {
        guard loaded else { return }
        let next = draft
        networksError = Self.problem(next, .networks)
        dnsError = Self.problem(next, .dns)
        domainsError = Self.problem(next, .domains)
        guard networksError == nil, dnsError == nil, domainsError == nil, next != saved else { return }
        do {
            try TunnelLibrary.saveSettings(next, for: name)
            saved = next
            error = nil
            model.objectWillChange.send()  // the reconnect banner depends on the saved settings
        } catch {
            self.error = "\(error)"
        }
    }

    /// The validation message for one group of fields, checked on its own.
    private static func problem(_ settings: TunnelSettings, _ field: Field) -> String? {
        var s = settings
        switch field {
        case .networks:
            s.dnsMode = .config
            s.dnsServers = []
            s.splitDNSDomains = []
        case .dns:
            s.routing = .config
            s.networks = []
            s.splitDNSDomains = []
        case .domains:
            s.routing = .config
            s.networks = []
            s.dnsMode = .config
            s.dnsServers = []
        case .username, .password:
            return nil
        }
        do {
            try s.validate()
            return nil
        } catch let error as ConfigError {
            return error.message
        } catch {
            return "\(error)"
        }
    }

    private func saveLogin() {
        let user = username.trimmingCharacters(in: .whitespaces)
        guard !user.isEmpty, !password.isEmpty else { return }
        do {
            try Keychain.saveCredentials(username: user, password: password, for: name)
            password = ""
            hasSavedLogin = true
            loginSaved = true
        } catch {
            self.error = "\(error)"
        }
    }

    private func forgetLogin() {
        guard Alerts.confirm(String(localized: "Forget the password for “\(name)”?"),
                             String(localized: "Bridge will ask for it the next time you connect."), button: String(localized: "Forget"), destructive: true) else { return }
        Keychain.deleteCredentials(for: name)
        username = ""
        password = ""
        hasSavedLogin = false
        loginSaved = false
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

    static func split(_ text: String) -> [String] {
        text.split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " || $0 == ";" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .reduce(into: [String]()) { list, item in if !list.contains(item) { list.append(item) } }
    }
}

// MARK: - Config editor

struct ConfigEditor: View {
    let name: String
    let kind: TunnelKind
    let brand: AddTunnelKind
    @State var text: String
    let onSave: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var error: String?

    init(name: String, kind: TunnelKind, brand: AddTunnelKind, text: String, onSave: @escaping () -> Void) {
        self.name = name
        self.kind = kind
        self.brand = brand
        _text = State(initialValue: text)
        self.onSave = onSave
    }

    /// Checks the text as the matching parser would when connecting.
    private var validation: (ok: Bool, message: String) {
        do {
            switch kind {
            case .amneziawg, .wireguard: _ = try TunnelConfig.parse(text)
            case .openvpn: _ = try OpenVPNConfig.parse(text)
            case .openconnect: _ = try OpenConnectConfig.parse(text)
            case .vless, .trojan, .hysteria2: _ = try ProxyLink.parse(text.trimmingCharacters(in: .whitespacesAndNewlines))
            }
            return (true, String(localized: "Valid \(kind.displayName) configuration"))
        } catch {
            return (false, "\(error)")
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                KindTile(kind: brand, size: 20, shadow: false)
                Text("Edit “\(name)”").font(.headline)
            }
            TextEditor(text: $text)
                .font(.system(size: 12, design: .monospaced))
                .autocorrectionDisabled()
                .scrollContentBackground(.hidden)
                .padding(6)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.secondary.opacity(0.25)))
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
                    .textSelection(.enabled)
            }
            HStack(spacing: 8) {
                let check = validation
                Label {
                    Text(check.message).lineLimit(1).truncationMode(.tail)
                } icon: {
                    Image(systemName: check.ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .foregroundStyle(check.ok ? .green : .red)
                }
                .font(.callout)
                Text("Applies the next time you connect.").font(.caption).foregroundStyle(.secondary)
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
                .disabled(!check.ok)
            }
        }
        .padding(20)
        .frame(minWidth: 660, minHeight: 480)
    }
}

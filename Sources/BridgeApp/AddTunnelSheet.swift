import AppKit
import BridgeClient
import BridgeCore
import SwiftUI
import UniformTypeIdentifiers

/// What the "+" button in Manage Tunnels can add.
enum AddTunnelKind: String, CaseIterable, Identifiable {
    case amneziawg, wireguard, openvpn
    case vless, trojan, hysteria2
    case anyconnect, fortinet, globalprotect, pulse, juniper, f5, array

    var id: String { rawValue }

    enum Source: Equatable {
        case file(extensions: [String])
        case link
        case server(OpenConnectConfig.VPNProtocol)
    }

    var source: Source {
        switch self {
        case .amneziawg, .wireguard: .file(extensions: ["conf"])
        case .openvpn: .file(extensions: ["ovpn", "conf"])
        case .vless, .trojan, .hysteria2: .link
        case .anyconnect: .server(.anyconnect)
        case .fortinet: .server(.fortinet)
        case .globalprotect: .server(.gp)
        case .pulse: .server(.pulse)
        case .juniper: .server(.nc)
        case .f5: .server(.f5)
        case .array: .server(.array)
        }
    }

    var title: String {
        switch self {
        case .amneziawg: "AmneziaWG"
        case .wireguard: "WireGuard"
        case .openvpn: "OpenVPN"
        case .vless: "VLESS"
        case .trojan: "Trojan"
        case .hysteria2: "Hysteria 2"
        case .anyconnect: "Cisco AnyConnect"
        case .fortinet: "Fortinet FortiGate"
        case .globalprotect: "Palo Alto GlobalProtect"
        case .pulse: "Ivanti Connect Secure"
        case .juniper: "Juniper Network Connect"
        case .f5: "F5 BIG-IP"
        case .array: "Array Networks"
        }
    }

    var subtitle: String {
        switch self {
        case .amneziawg, .wireguard: ".conf file"
        case .openvpn: ".ovpn file"
        case .vless: "vless:// link"
        case .trojan: "trojan:// link"
        case .hysteria2: "hysteria2:// link"
        case .anyconnect: "and ocserv"
        case .pulse: "Pulse Secure"
        default: "Server login"
        }
    }

    /// Short label on the tile, like the protocol badges elsewhere in Bridge.
    var badge: String {
        switch self {
        case .amneziawg: "AWG"
        case .wireguard: "WG"
        case .openvpn: "OVPN"
        case .vless: "VLESS"
        case .trojan: "TRJ"
        case .hysteria2: "HY2"
        case .anyconnect: "AC"
        case .fortinet: "FTG"
        case .globalprotect: "GP"
        case .pulse: "ICS"
        case .juniper: "JNC"
        case .f5: "F5"
        case .array: "AN"
        }
    }

    var color: Color {
        switch self {
        case .amneziawg: Color(red: 0.20, green: 0.62, blue: 0.36)
        case .wireguard: Color(red: 0.62, green: 0.13, blue: 0.16)
        case .openvpn: Color(red: 0.93, green: 0.49, blue: 0.13)
        case .vless: Color(red: 0.49, green: 0.30, blue: 0.80)
        case .trojan: Color(red: 0.36, green: 0.42, blue: 0.50)
        case .hysteria2: Color(red: 0.10, green: 0.56, blue: 0.80)
        case .anyconnect: Color(red: 0.08, green: 0.40, blue: 0.75)
        case .fortinet: Color(red: 0.85, green: 0.20, blue: 0.15)
        case .globalprotect: Color(red: 0.05, green: 0.55, blue: 0.60)
        case .pulse: Color(red: 0.80, green: 0.25, blue: 0.20)
        case .juniper: Color(red: 0.20, green: 0.40, blue: 0.20)
        case .f5: Color(red: 0.75, green: 0.08, blue: 0.20)
        case .array: Color(red: 0.90, green: 0.40, blue: 0.10)
        }
    }

    static let groups: [(title: String, kinds: [AddTunnelKind])] = [
        ("Config file", [.amneziawg, .wireguard, .openvpn]),
        ("Share link", [.vless, .trojan, .hysteria2]),
        ("Server login · OpenConnect", [.anyconnect, .fortinet, .globalprotect, .pulse, .juniper, .f5, .array]),
    ]
}

/// The "+" sheet of Manage Tunnels: pick a kind of VPN, then add it from a file,
/// pasted links, or a server address.
struct AddTunnelSheet: View {
    @EnvironmentObject var model: AppModel
    /// Called with the first added tunnel, or nil when cancelled.
    let onDone: (String?) -> Void

    @State private var selected: AddTunnelKind?
    @State private var step: AddTunnelKind?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let step {
                AddTunnelDetail(kind: step, onBack: { self.step = nil }, onDone: onDone)
            } else {
                picker
            }
        }
        .frame(width: 680, height: 640)
    }

    private var picker: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add Tunnel").font(.title2.weight(.semibold))
                Text("Choose the kind of VPN you have.").foregroundStyle(.secondary)
            }
            .padding([.horizontal, .top], 24)
            .padding(.bottom, 12)

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    ForEach(AddTunnelKind.groups, id: \.title) { group in
                        VStack(alignment: .leading, spacing: 8) {
                            Text(group.title.uppercased())
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 3), spacing: 10) {
                                ForEach(group.kinds) { kind in
                                    KindCard(kind: kind, selected: selected == kind)
                                        .onTapGesture(count: 2) { step = kind }
                                        .simultaneousGesture(TapGesture().onEnded { selected = kind })
                                }
                            }
                        }
                    }
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 12)
            }

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { onDone(nil) }
                    .keyboardShortcut(.cancelAction)
                Button("Continue") { step = selected }
                    .keyboardShortcut(.defaultAction)
                    .disabled(selected == nil)
            }
            .padding(16)
        }
    }
}

private struct KindCard: View {
    let kind: AddTunnelKind
    let selected: Bool

    var body: some View {
        HStack(spacing: 12) {
            KindTile(kind: kind, size: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(kind.title).font(.system(size: 13, weight: .semibold)).lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Text(kind.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .frame(maxWidth: .infinity, minHeight: 64, maxHeight: 64, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 10)
            .strokeBorder(selected ? Color.accentColor : Color.primary.opacity(0.10), lineWidth: selected ? 2 : 1))
        .contentShape(RoundedRectangle(cornerRadius: 10))
    }
}

/// A colored tile with the protocol's short label.
struct KindTile: View {
    let kind: AddTunnelKind
    let size: CGFloat

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.24)
            .fill(LinearGradient(colors: [kind.color.opacity(0.85), kind.color], startPoint: .top, endPoint: .bottom))
            .frame(width: size, height: size)
            .overlay(
                Text(kind.badge)
                    .font(.system(size: size * (kind.badge.count > 3 ? 0.24 : 0.32), weight: .heavy, design: .rounded))
                    .foregroundStyle(.white)
                    .minimumScaleFactor(0.6)
                    .padding(.horizontal, 3)
            )
    }
}

// MARK: - Second step

private struct AddTunnelDetail: View {
    @EnvironmentObject var model: AppModel
    let kind: AddTunnelKind
    let onBack: () -> Void
    let onDone: (String?) -> Void

    @State private var errors: [String] = []
    // Links
    @State private var linksText = ""
    // Server
    @State private var server = ""
    @State private var username = ""
    @State private var group = ""
    @State private var name = ""
    @State private var dropTargeted = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 14) {
                KindTile(kind: kind, size: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Add \(kind.title)").font(.title2.weight(.semibold))
                    Text(headline).foregroundStyle(.secondary)
                }
            }
            .padding(24)

            Group {
                switch kind.source {
                case .file(let extensions): fileStep(extensions)
                case .link: linkStep
                case .server(let p): serverStep(p)
                }
            }
            .padding(.horizontal, 24)
            .frame(maxHeight: .infinity, alignment: .top)

            if !errors.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(errors, id: \.self) { error in
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .font(.callout)
                            .textSelection(.enabled)
                    }
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 8)
            }

            Divider()
            HStack {
                Button("Back") { onBack() }
                Spacer()
                Button("Cancel") { onDone(nil) }
                    .keyboardShortcut(.cancelAction)
                switch kind.source {
                case .link:
                    Button("Add") { addLinks() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(linkCount == 0)
                case .server(let p):
                    Button("Add") { addServer(p) }
                        .keyboardShortcut(.defaultAction)
                        .disabled(server.trimmingCharacters(in: .whitespaces).isEmpty)
                case .file:
                    EmptyView()  // the drop zone has the Choose File button
                }
            }
            .padding(16)
        }
        .onAppear {
            if kind.source == .link, let clip = NSPasteboard.general.string(forType: .string),
               (try? TunnelLibrary.proxyLinks(in: clip))?.isEmpty == false {
                linksText = clip
            }
        }
    }

    private var headline: String {
        switch kind.source {
        case .file: "Import the configuration file your provider or administrator gave you."
        case .link: "Paste one or more links, or a subscription."
        case .server: "Bridge asks for the password, one-time code or SSO sign-in when you connect."
        }
    }

    // MARK: File

    private func fileStep(_ extensions: [String]) -> some View {
        VStack(spacing: 14) {
            RoundedRectangle(cornerRadius: 14)
                .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [7, 5]))
                .foregroundStyle(dropTargeted ? Color.accentColor : Color.secondary.opacity(0.5))
                .background(RoundedRectangle(cornerRadius: 14).fill(dropTargeted ? Color.accentColor.opacity(0.08) : .clear))
                .overlay(
                    VStack(spacing: 10) {
                        Image(systemName: "doc.badge.plus").font(.system(size: 36)).foregroundStyle(.secondary)
                        Text("Drop \(extensions.map { ".\($0)" }.joined(separator: " or ")) files here")
                            .font(.headline)
                        Button("Choose File…") { chooseFiles() }
                    }
                )
                .frame(height: 300)
                .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
                    loadDropped(providers)
                    return true
                }
            Text(kind == .openvpn
                 ? "Certificates and keys the .ovpn file points to are copied into Bridge; a login file goes to the Keychain."
                 : "Several files can be imported at once.")
                .font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func chooseFiles() {
        guard case .file(let extensions) = kind.source else { return }
        let panel = NSOpenPanel()
        panel.title = "Import \(kind.title)"
        panel.prompt = "Import"
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.allowedContentTypes = extensions.compactMap { UTType(filenameExtension: $0) }
        guard panel.runModal() == .OK else { return }
        importFiles(panel.urls)
    }

    private func loadDropped(_ providers: [NSItemProvider]) {
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
        group.notify(queue: .main) { importFiles(collected.lock.withLock { collected.urls }) }
    }

    private func importFiles(_ urls: [URL]) {
        guard !urls.isEmpty else { return }
        let result = model.importFiles(urls)
        errors = result.errors
        if result.errors.isEmpty, let first = result.names.first { onDone(first) }
    }

    // MARK: Links

    private var linkCount: Int { (try? TunnelLibrary.proxyLinks(in: linksText))?.count ?? 0 }

    private var linkStep: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextEditor(text: $linksText)
                .font(.system(size: 12, design: .monospaced))
                .autocorrectionDisabled()
                .scrollContentBackground(.hidden)
                .padding(6)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.secondary.opacity(0.25)))
                .overlay(alignment: .topLeading) {
                    if linksText.isEmpty {
                        Text("\(kind == .hysteria2 ? "hysteria2" : kind.rawValue)://…")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.tertiary)
                            .padding(11)
                            .allowsHitTesting(false)
                    }
                }
                .frame(height: 230)
            HStack {
                Text(linkCount == 0 ? "No links yet" : "\(linkCount) link\(linkCount == 1 ? "" : "s") found")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Paste") { linksText = NSPasteboard.general.string(forType: .string) ?? linksText }
                Button("Open File…") {
                    let panel = NSOpenPanel()
                    panel.allowsMultipleSelection = false
                    guard panel.runModal() == .OK, let url = panel.url,
                          let text = try? String(contentsOf: url, encoding: .utf8) else { return }
                    linksText = text
                }
            }
            Text("VLESS, Trojan and Hysteria 2 links can be mixed; each becomes a tunnel.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func addLinks() {
        do {
            let result = try model.importLinks(linksText)
            errors = result.errors
            if result.errors.isEmpty, let first = result.names.first { onDone(first) }
        } catch {
            errors = [error.localizedDescription]
        }
    }

    // MARK: Server

    private func serverStep(_ p: OpenConnectConfig.VPNProtocol) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Form {
                TextField("Server", text: $server, prompt: Text("vpn.example.com or vpn.example.com/group"))
                TextField("Username", text: $username, prompt: Text("Optional"))
                TextField("Group", text: $group, prompt: Text("Optional"))
                TextField("Name", text: $name, prompt: Text("Optional, e.g. Office"))
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .frame(height: 210)
            HStack {
                Text(p == .anyconnect
                     ? "Works with Cisco ASA / Secure Firewall and ocserv servers."
                     : "Uses OpenConnect's \(p.displayName) support. Bridge is tested with AnyConnect-compatible "
                        + "servers; tell us how it works with yours.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Import Profile…") { importProfile() }
                    .help("Import a .openconnect profile file")
            }
        }
    }

    private func addServer(_ p: OpenConnectConfig.VPNProtocol) {
        var config = OpenConnectConfig(vpnProtocol: p, server: server.trimmingCharacters(in: .whitespaces))
        let u = username.trimmingCharacters(in: .whitespaces), g = group.trimmingCharacters(in: .whitespaces)
        config.username = u.isEmpty ? nil : u
        config.group = g.isEmpty ? nil : g
        let n = name.trimmingCharacters(in: .whitespaces)
        do {
            onDone(try model.addOpenConnect(config, name: n.isEmpty ? nil : n))
        } catch {
            errors = [error.localizedDescription]
        }
    }

    private func importProfile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "openconnect")].compactMap { $0 }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        importFiles([url])
    }
}

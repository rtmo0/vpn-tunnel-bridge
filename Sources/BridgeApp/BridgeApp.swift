import AppKit
import BridgeClient
import BridgeCore
import SwiftUI

@main
struct BridgeApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuContent()
                .environmentObject(model)
        } label: {
            Image(nsImage: MenuBarIcon.image(model.menuIconState, frame: model.animationFrame))
        }
        .menuBarExtraStyle(.window)
    }
}

struct MenuContent: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            helperBanner
            tunnelList
            if let message = model.message {
                Divider()
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    Text(message).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                    Button {
                        model.message = nil
                    } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                }
                .padding(10)
            }
            Divider()
            footer
        }
        .frame(width: 360)
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 26, height: 26)
            VStack(alignment: .leading, spacing: 0) {
                Text("Bridge").font(.headline)
                Text(model.anyConnected ? "Protected" : "Tunnel Bridge")
                    .font(.caption)
                    .foregroundStyle(model.anyConnected ? Color.green : Color.secondary)
            }
            Spacer()
            if model.anyActive {
                Button("Disconnect All") { model.disconnectAll() }
                    .buttonStyle(.link)
                    .font(.callout)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    @ViewBuilder private var helperBanner: some View {
        switch model.helper {
        case .ready:
            EmptyView()
        case .notInstalled, .outdated:
            VStack(alignment: .leading, spacing: 6) {
                if case .outdated = model.helper {
                    Text("The network helper needs an update.").font(.callout.weight(.semibold))
                } else {
                    Text("Install the network helper to connect.").font(.callout.weight(.semibold))
                }
                Text("It runs the VPN backends with administrator rights. You will be asked for your password once.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Button {
                    model.installHelper()
                } label: {
                    if model.installing {
                        ProgressView().controlSize(.small)
                    } else {
                        Text(model.helper == .notInstalled ? "Install Helper…" : "Update Helper…")
                    }
                }
                .disabled(model.installing)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.accentColor.opacity(0.08))
            Divider()
        }
    }

    @ViewBuilder private var tunnelList: some View {
        if model.rows.isEmpty {
            VStack(spacing: 6) {
                Image(systemName: "tray").font(.title2).foregroundStyle(.secondary)
                Text("No tunnels yet").font(.callout.weight(.semibold))
                Text("Import a WireGuard / AmneziaWG .conf or an OpenVPN .ovpn file.")
                    .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
                Button("Import…") { model.importConfigs() }.padding(.top, 4)
            }
            .frame(maxWidth: .infinity)
            .padding(20)
        } else {
            ScrollView {
                VStack(spacing: 0) {
                    ForEach(model.rows) { row in
                        TunnelRowView(row: row)
                        if row.id != model.rows.last?.id { Divider().padding(.leading, 50) }
                    }
                }
            }
            .frame(maxHeight: 360)
            .fixedSize(horizontal: false, vertical: model.rows.count <= 6)
        }
    }

    private var footer: some View {
        HStack(spacing: 14) {
            Button {
                model.importConfigs()
            } label: {
                Label("Import…", systemImage: "plus")
            }
            Button {
                model.openLogs()
            } label: {
                Label("Logs", systemImage: "doc.text.magnifyingglass")
            }
            Spacer()
            Menu {
                Button("Reinstall Helper…") { model.installHelper() }
                Button("Open Tunnels Folder") {
                    try? FileManager.default.createDirectory(at: TunnelLibrary.directory, withIntermediateDirectories: true)
                    NSWorkspace.shared.open(TunnelLibrary.directory)
                }
                Divider()
                Button("Quit Bridge") { NSApp.terminate(nil) }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

struct TunnelRowView: View {
    @EnvironmentObject var model: AppModel
    let row: AppModel.Row

    private var busy: Bool { model.busy.contains(row.name) }

    private var dotColor: Color {
        if busy { return .orange }
        guard let status = row.status else { return Color(nsColor: .tertiaryLabelColor) }
        return status.connected ? .green : .orange
    }

    private var subtitle: String {
        var parts: [String] = []
        if busy {
            parts.append(row.status == nil ? "Connecting…" : "Disconnecting…")
        } else if let status = row.status {
            parts.append(status.state)
            if status.connected {
                parts.append("↓ \(Self.bytes(status.rxBytes))  ↑ \(Self.bytes(status.txBytes))")
            }
        } else {
            parts.append("Disconnected")
        }
        return parts.joined(separator: " · ")
    }

    static func bytes(_ count: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .binary)
    }

    var body: some View {
        HStack(spacing: 10) {
            ProtocolBadge(kind: row.kind)
                .overlay(alignment: .bottomTrailing) {
                    StatusDot(color: dotColor).offset(x: 3, y: 3)
                }
                .opacity(row.status == nil && !busy ? 0.75 : 1)
            VStack(alignment: .leading, spacing: 2) {
                Text(row.name).font(.body.weight(.medium)).lineLimit(1)
                Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                if let status = row.status, status.connected, let server = status.server {
                    Text(server).font(.caption2).foregroundStyle(.tertiary).lineLimit(1)
                }
            }
            Spacer()
            if busy {
                ProgressView().controlSize(.small)
            } else {
                Toggle("", isOn: Binding(
                    get: { row.status != nil },
                    set: { _ in model.toggle(row) }))
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .labelsHidden()
                    .disabled(!model.helperReady || !row.saved && row.status == nil)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .contentShape(Rectangle())
        .contextMenu {
            if row.status != nil {
                Button("Disconnect") { model.disconnect(row.name) }
            } else if row.saved {
                Button("Connect") { model.connect(row.name) }
            }
            if row.saved {
                Button("Show in Finder") { model.revealInFinder(row) }
                if row.kind == .openvpn { Button("Forget Saved Password") { model.forgetPasswords(row) } }
                Divider()
                Button("Remove…", role: .destructive) { model.remove(row) }
            }
        }
        .help(row.status?.warnings.joined(separator: "\n") ?? "")
    }
}

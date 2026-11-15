import AppKit
import BridgeClient
import BridgeCore
import ServiceManagement
import SwiftUI

/// App-wide settings (⌘,): general options, updates, the helper, routing profiles
/// and licenses. Per-tunnel settings stay in Manage Tunnels.
enum SettingsWindow {
    enum Tab: Hashable { case general, profiles, advanced }

    final class State: ObservableObject {
        @Published var tab: Tab = .general
    }

    private static var window: NSWindow?
    private static let state = State()
    /// Set once by the menu controller, which owns the updater.
    static var updater: Updater?

    static func show(model: AppModel, tab: Tab? = nil) {
        if let tab { state.tab = tab }
        if window == nil {
            let root = SettingsView(updater: updater).environmentObject(model).environmentObject(state)
            let window = NSWindow(contentViewController: NSHostingController(rootView: root))
            window.title = String(localized: "Bridge Settings")
            window.styleMask = [.titled, .closable, .miniaturizable]
            window.isReleasedWhenClosed = false
            window.center()
            self.window = window
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
        window?.orderFrontRegardless()
    }
}

enum Preferences {
    static let showMenuDetails = "showMenuDetails"
    static let autoCheckUpdates = "autoCheckUpdates"
    static let lastUpdateCheck = "lastUpdateCheck"

    static func register() {
        UserDefaults.standard.register(defaults: [showMenuDetails: true, autoCheckUpdates: true])
    }
}

private struct SettingsView: View {
    let updater: Updater?
    @EnvironmentObject var state: SettingsWindow.State

    var body: some View {
        TabView(selection: $state.tab) {
            GeneralSettings(updater: updater)
                .tabItem { Label("General", systemImage: "gearshape") }
                .tag(SettingsWindow.Tab.general)
            ProfilesSettings()
                .tabItem { Label("Routing Profiles", systemImage: "point.topleft.down.to.point.bottomright.curvepath") }
                .tag(SettingsWindow.Tab.profiles)
            AdvancedSettings()
                .tabItem { Label("Advanced", systemImage: "slider.horizontal.3") }
                .tag(SettingsWindow.Tab.advanced)
        }
        .frame(width: 600, height: 470)
    }
}

// MARK: - General

private struct GeneralSettings: View {
    let updater: Updater?
    @EnvironmentObject var model: AppModel
    @AppStorage(Preferences.showMenuDetails) private var showMenuDetails = true
    @AppStorage(Preferences.autoCheckUpdates) private var autoCheckUpdates = true
    @AppStorage(Preferences.lastUpdateCheck) private var lastCheck: Double = 0
    @State private var openAtLogin = SMAppService.mainApp.status == .enabled
    @State private var loginError: String?

    var body: some View {
        Form {
            Section("App") {
                Toggle("Open Bridge at login", isOn: $openAtLogin)
                    .onChange(of: openAtLogin) { _, enabled in setOpenAtLogin(enabled) }
                if let loginError {
                    Text(loginError).font(.caption).foregroundStyle(.red)
                }
                Toggle("Show speed under connected tunnels in the menu", isOn: $showMenuDetails)
                    .onChange(of: showMenuDetails) { _, _ in model.objectWillChange.send(); model.onChange() }
            }
            Section("Updates") {
                Toggle("Check for updates automatically", isOn: $autoCheckUpdates)
                LabeledContent {
                    Button("Check Now") { updater?.check(userInitiated: true) }
                } label: {
                    Text("Bridge \(Updater.currentVersion)")
                    if lastCheck > 0 {
                        Text("Last checked \(Date(timeIntervalSince1970: lastCheck).formatted(.relative(presentation: .named)))")
                    }
                }
            }
            Section("Helper and files") {
                LabeledContent {
                    Button(model.helper == .notInstalled ? String(localized: "Install…") : String(localized: "Reinstall…")) { model.installHelper() }
                        .disabled(model.installing)
                } label: {
                    Text("Network helper")
                    HStack(spacing: 5) {
                        Circle().fill(helperColor).frame(width: 7, height: 7)
                        Text(helperText)
                    }
                }
                LabeledContent("Tunnels folder") {
                    Button("Show in Finder") { model.openTunnelsFolder() }
                }
                LabeledContent("Logs") {
                    Button("Open Logs") { model.openLogs() }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var helperText: String {
        if model.installing { return String(localized: "Installing…") }
        switch model.helper {
        case .ready: return String(localized: "Installed, matches the app")
        case .outdated: return String(localized: "Older than the app")
        case .notInstalled: return String(localized: "Not installed")
        }
    }

    private var helperColor: Color {
        switch model.helper {
        case .ready: Color(nsColor: Theme.good)
        case .outdated: Color(nsColor: Theme.busy)
        case .notInstalled: Color(nsColor: Theme.critical)
        }
    }

    private func setOpenAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            loginError = nil
        } catch {
            loginError = error.localizedDescription
            openAtLogin = SMAppService.mainApp.status == .enabled
        }
    }
}

// MARK: - Routing profiles

private struct ProfilesSettings: View {
    @EnvironmentObject var model: AppModel
    @State private var selected: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("A routing profile decides per site and network what goes through the VPN, what goes direct and what is blocked. It works with VLESS, Trojan and Hysteria 2 tunnels.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            List(selection: $selected) {
                ForEach(model.routingProfiles, id: \.self) { name in
                    HStack {
                        Image(systemName: "globe").foregroundStyle(.secondary)
                        Text(name)
                        Spacer()
                        Text(usage(name)).foregroundStyle(.secondary).font(.callout)
                    }
                    .padding(.vertical, 4)
                    .tag(name)
                }
            }
            .listStyle(.bordered(alternatesRowBackgrounds: false))
            .overlay {
                if model.routingProfiles.isEmpty {
                    Text("No routing profiles").foregroundStyle(.secondary)
                }
            }
            HStack(spacing: 8) {
                Menu {
                    Button("Import from File…") { model.importRoutingProfile(fromClipboard: false) { selected = $0 } }
                    Button("Paste happ:// Link or JSON") { model.importRoutingProfile(fromClipboard: true) { selected = $0 } }
                } label: {
                    Image(systemName: "plus")
                }
                .menuIndicator(.hidden)
                .fixedSize()
                .help("Add a routing profile")
                Button {
                    if let selected, model.removeRoutingProfile(selected) { self.selected = nil }
                } label: {
                    Image(systemName: "minus")
                }
                .disabled(selected == nil)
                .help("Remove the selected profile")
                Spacer()
                Button("Update Geo Files") { if let selected { model.updateRoutingProfile(selected) } }
                    .disabled(selected == nil)
            }
            Text("Removing a profile switches the tunnels that use it back to sending all traffic through the VPN.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(20)
    }

    private func usage(_ profile: String) -> String {
        let count = model.rows.filter { $0.saved && TunnelLibrary.settings(for: $0.name).routingProfile == profile }.count
        return count == 0 ? String(localized: "not used") : String(localized: "used by \(count) tunnels")
    }
}

// MARK: - Advanced

private struct AdvancedSettings: View {
    var body: some View {
        Form {
            Section("About Bridge") {
                LabeledContent("Version", value: Updater.currentBuild)
                LabeledContent("Source code") {
                    Link("github.com/\(Updater.repository)", destination: URL(string: "https://github.com/\(Updater.repository)")!)
                }
            }
            Section("Licenses") {
                Text("Free and open source under the MIT License. Use, copy, modify and distribute it freely; provided “as is”, without warranty.")
                    .fixedSize(horizontal: false, vertical: true)
                Text("Includes amneziawg-go (MIT), OpenVPN (GPL-2.0), OpenConnect (LGPL-2.1) and Xray-core (MPL-2.0).")
                    .fixedSize(horizontal: false, vertical: true)
                Text("Product names and logos are trademarks of their owners, shown to identify compatible services; logo artwork from Simple Icons (CC0).")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
    }
}

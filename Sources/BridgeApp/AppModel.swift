import AppKit
import UniformTypeIdentifiers
import BridgeClient
import BridgeCore
import Foundation

/// App state: saved tunnels, live statuses from the helper, and actions.
/// Everything runs on the main thread; slow helper calls go to a background queue.
final class AppModel: ObservableObject {
    struct Row: Equatable {
        let name: String
        let kind: TunnelKind
        var status: TunnelStatus?
        var saved: Bool
        /// Which logo to show: OpenConnect tunnels are told apart by their VPN protocol.
        var brand: AddTunnelKind

        static func == (a: Row, b: Row) -> Bool {
            a.name == b.name && a.kind == b.kind && a.saved == b.saved && a.brand == b.brand
                && a.status?.state == b.status?.state && a.status?.connected == b.status?.connected
                && a.status?.rxBytes == b.status?.rxBytes && a.status?.txBytes == b.status?.txBytes
                && a.status?.directSites == b.status?.directSites
        }
    }

    private(set) var rows: [Row] = []
    private(set) var helper: HelperClient.Availability = .notInstalled
    private(set) var busy: Set<String> = []
    private(set) var installing = false
    private(set) var rates: [String: (rx: Double, tx: Double)] = [:]
    /// Tunnels that dropped with the kill switch on: the Mac has no internet until lifted.
    private(set) var killSwitchHolds: [String] = []
    /// The settings each connected tunnel was brought up with; a saved change that differs
    /// from these needs a reconnect to take effect.
    private(set) var appliedSettings: [String: TunnelSettings] = [:]
    /// Tunnels the user disconnected (or is reconnecting): their going down is no news.
    private var userStopped: Set<String> = []

    func needsReconnect(_ name: String) -> Bool {
        guard isActive(name), !busy.contains(name), let applied = appliedSettings[name] else { return false }
        return applied != TunnelLibrary.settings(for: name)
    }

    /// Called on the main thread whenever something visible changed.
    var onChange: () -> Void = {}

    private var lastCounters: [String: (rx: UInt64, tx: UInt64, at: Date)] = [:]
    private var refreshing = false
    private let work = DispatchQueue(label: "com.rtmo0.bridge.app.work", attributes: .concurrent)

    init() {
        // Local proxies are the app's own processes: they end with it.
        NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil,
                                               queue: nil) { _ in LocalProxies.shared.stopAll() }
        LocalProxies.shared.onExit = { [weak self] _ in DispatchQueue.main.async { self?.refresh() } }
    }

    private func changed() {
        objectWillChange.send()
        onChange()
    }

    var helperReady: Bool {
        if case .ready = helper { return true }
        return false
    }

    var capabilities: [TunnelKind] {
        if case let .ready(capabilities) = helper { return capabilities }
        return []
    }

    var connectedRows: [Row] { rows.filter { $0.status?.connected == true } }

    var iconState: MenuBarIcon.State {
        if !busy.isEmpty || rows.contains(where: { $0.status != nil && $0.status?.connected == false }) {
            return .connecting
        }
        let connected = connectedRows.count
        if connected > 0 { return .connected(count: connected) }
        if case .outdated = helper { return .error }
        if !killSwitchHolds.isEmpty { return .error }
        return .disconnected
    }

    // MARK: Refresh

    func refresh() {
        guard !refreshing else { return }
        refreshing = true
        // While a connection attempt runs the helper is busy; keep the last known statuses.
        let skipStatus = !busy.isEmpty
        let previous = rows
        work.async {
            let saved = TunnelLibrary.list()
            let brands = Dictionary(uniqueKeysWithValues: saved.map { ($0.name, AddTunnelKind.brand(of: $0)) })
            let availability = HelperClient.availability(expectedBuild: Updater.currentBuild)
            var statuses: [TunnelStatus]?
            var holds: [String]?
            if case .ready = availability, !skipStatus, let full = try? HelperClient.fullStatus() {
                statuses = full.tunnels
                holds = full.killSwitchHolds
            }
            let proxies = LocalProxies.shared.statuses()
            DispatchQueue.main.async {
                self.refreshing = false
                let proxyNames = Set(proxies.map(\.name))
                let active = (statuses ?? previous.compactMap(\.status)).filter { !proxyNames.contains($0.name) } + proxies
                var rows = saved.map { entry in
                    Row(name: entry.name, kind: entry.kind, status: active.first { $0.name == entry.name }, saved: true,
                        brand: brands[entry.name] ?? AddTunnelKind(entry.kind))
                }
                for status in active where !rows.contains(where: { $0.name == status.name }) {
                    rows.append(Row(name: status.name, kind: status.kind, status: status, saved: false,
                                    brand: AddTunnelKind(status.kind)))
                }
                if case .ready = availability {} else {
                    // Without the helper only local proxies (run by the app) can be up.
                    rows = rows.map {
                        Row(name: $0.name, kind: $0.kind, status: proxyNames.contains($0.name) ? $0.status : nil,
                            saved: $0.saved, brand: $0.brand)
                    }
                }
                let ratesChanged = (statuses != nil || !proxies.isEmpty) && self.updateRates(rows)
                // Tunnels already up when the app started: assume their current settings apply.
                for row in rows where row.status != nil && self.appliedSettings[row.name] == nil && row.saved {
                    self.appliedSettings[row.name] = TunnelLibrary.settings(for: row.name)
                }
                for name in self.appliedSettings.keys where !rows.contains(where: { $0.name == name && $0.status != nil }) {
                    if !self.busy.contains(name) { self.appliedSettings[name] = nil }
                }
                // Row == leaves out handshakes, addresses and warnings; compare whole statuses.
                let changed = rows != self.rows || Self.statusData(rows) != Self.statusData(self.rows)
                    || availability != self.helper || ratesChanged
                    || (holds != nil && holds != self.killSwitchHolds)
                if statuses != nil { self.notifyDrops(from: self.rows, to: rows, holds: holds ?? []) }
                if let holds { self.killSwitchHolds = holds }
                self.rows = rows
                self.helper = availability
                // Only on a real change: this runs every 2 s, and each objectWillChange makes
                // SwiftUI track the model again.
                if changed { self.changed() }
            }
        }
    }

    /// A connected tunnel that went away without the user asking becomes a notification.
    private func notifyDrops(from old: [Row], to new: [Row], holds: [String]) {
        let up = Set(new.filter { $0.status != nil }.map(\.name))
        for row in old where row.status?.connected == true && !up.contains(row.name)
            && !busy.contains(row.name) && !userStopped.contains(row.name) {
            let body = holds.contains(row.name)
                ? String(localized: "The kill switch keeps traffic blocked until you reconnect or unblock it in the menu.")
                : String(localized: "The connection to the server was lost.")
            Notifier.post(String(localized: "“\(row.name)” disconnected"), body)
        }
        userStopped = userStopped.filter { up.contains($0) || busy.contains($0) }
    }

    private static let statusEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return encoder
    }()

    /// Everything the helper reported, for telling whether anything shown changed.
    private static func statusData(_ rows: [Row]) -> Data? {
        try? statusEncoder.encode(rows.map(\.status))
    }

    /// Returns whether any shown rate changed.
    private func updateRates(_ rows: [Row]) -> Bool {
        let now = Date()
        var next: [String: (rx: UInt64, tx: UInt64, at: Date)] = [:]
        var rates: [String: (rx: Double, tx: Double)] = [:]
        for row in rows {
            guard let status = row.status else { continue }
            if let last = lastCounters[row.name], status.rxBytes >= last.rx, status.txBytes >= last.tx {
                let dt = max(0.5, now.timeIntervalSince(last.at))
                rates[row.name] = (Double(status.rxBytes - last.rx) / dt, Double(status.txBytes - last.tx) / dt)
            }
            next[row.name] = (status.rxBytes, status.txBytes, now)
        }
        lastCounters = next
        let changed = rates.count != self.rates.count || rates.contains { name, rate in
            guard let old = self.rates[name] else { return true }
            return old.rx != rate.rx || old.tx != rate.tx
        }
        self.rates = rates
        return changed
    }

    // MARK: Connect / disconnect

    func toggle(_ name: String) {
        guard !busy.contains(name) else { return }
        if rows.first(where: { $0.name == name })?.status != nil { disconnect(name) } else { connect(name) }
    }

    func connect(_ name: String) {
        let settings = TunnelLibrary.settings(for: name)
        if settings.isLocalProxy, rows.first(where: { $0.name == name })?.kind.usesXray == true {
            connectLocalProxy(name, settings: settings)
            return
        }
        guard helperReady else {
            let installed = helper != .notInstalled
            let title = installed ? String(localized: "Update the network helper?") : String(localized: "Install the network helper?")
            if Alerts.confirm(title, String(localized: "Bridge needs its helper to connect “\(name)”. macOS will ask for your administrator password once."),
                              button: installed ? String(localized: "Update and Connect") : String(localized: "Install and Connect"), style: .informational) {
                installHelper { [weak self] in self?.connect(name) }
            }
            return
        }
        // A helper older than the app may lack a backend: offer the fix instead of a dead end.
        if let kind = rows.first(where: { $0.name == name })?.kind,
           kind == .openvpn || kind == .openconnect || kind.usesXray, !capabilities.contains(kind) {
            let choice = Alerts.choose(String(localized: "Could not connect “\(name)”"),
                                       String(localized: "The installed helper is older than the app and has no \(kind.displayName) support."),
                                       buttons: [String(localized: "Update Helper and Retry"), String(localized: "Cancel")])
            if choice == 0 { installHelper { [weak self] in self?.connect(name) } }
            return
        }
        userStopped.remove(name)
        setBusy(name, true)
        work.async {
            var failure: String?
            var connected = false
            do {
                let (text, kind) = try TunnelLibrary.load(name)
                _ = try Connector.connect(name: name, text: text, kind: kind, settings: settings,
                                          openConnectUI: AppOpenConnectUI()) { prompt in
                    DispatchQueue.main.sync { Prompter.ask(prompt) }
                }
                connected = true
            } catch let error as ClientError where error.description == "Cancelled" {
                failure = nil
            } catch {
                failure = error.localizedDescription
            }
            DispatchQueue.main.async {
                if connected { self.appliedSettings[name] = settings }
                self.setBusy(name, false)
                if let failure,
                   Alerts.choose(String(localized: "Could not connect “\(name)”"), failure, buttons: [String(localized: "OK"), String(localized: "Show Log")], style: .warning) == 1 {
                    self.openLogs()
                }
                self.refresh()
            }
        }
    }

    /// Starts a tunnel as a local proxy, run by the app itself (no helper, no administrator rights).
    private func connectLocalProxy(_ name: String, settings: TunnelSettings) {
        userStopped.remove(name)
        setBusy(name, true)
        work.async {
            var failure: String?
            do {
                let (text, _) = try TunnelLibrary.load(name)
                var profile: RoutingProfile?
                if let profileName = settings.routingProfile {
                    let loaded = try RoutingProfiles.load(profileName)
                    try RoutingProfiles.checkAssets(loaded, name: profileName)
                    profile = loaded
                }
                try LocalProxies.shared.start(name: name, text: text, settings: settings, profile: profile)
            } catch {
                failure = error.localizedDescription
            }
            DispatchQueue.main.async {
                if failure == nil { self.appliedSettings[name] = settings }
                self.setBusy(name, false)
                if let failure,
                   Alerts.choose(String(localized: "Could not connect “\(name)”"), failure, buttons: [String(localized: "OK"), String(localized: "Show Log")], style: .warning) == 1 {
                    NSWorkspace.shared.open(LocalProxies.logURL(name))
                }
                self.refresh()
            }
        }
    }

    func disconnect(_ name: String) {
        userStopped.insert(name)
        if LocalProxies.shared.isRunning(name) {
            LocalProxies.shared.stop(name)
            refresh()
            return
        }
        setBusy(name, true)
        work.async {
            var failure: String?
            do { try HelperClient.disconnect(name) } catch { failure = error.localizedDescription }
            DispatchQueue.main.async {
                self.setBusy(name, false)
                if let failure { Alerts.show(String(localized: "Could not disconnect “\(name)”"), failure) }
                self.refresh()
            }
        }
    }

    /// Disconnects and connects again, e.g. to apply new settings.
    func reconnect(_ name: String) {
        userStopped.insert(name)
        setBusy(name, true)
        work.async {
            if LocalProxies.shared.isRunning(name) {
                LocalProxies.shared.stop(name)
            } else {
                try? HelperClient.disconnect(name)
            }
            DispatchQueue.main.async {
                self.setBusy(name, false)
                self.connect(name)
            }
        }
    }

    func isActive(_ name: String) -> Bool { rows.first { $0.name == name }?.status != nil }

    func releaseKillSwitch() {
        work.async {
            var failure: String?
            do { try HelperClient.releaseKillSwitch() } catch { failure = error.localizedDescription }
            DispatchQueue.main.async {
                if let failure { Alerts.show(String(localized: "Could not lift the kill switch"), failure) }
                self.refresh()
            }
        }
    }

    func disconnectAll() {
        userStopped.formUnion(rows.filter { $0.status != nil }.map(\.name))
        let helperTunnels = rows.contains { $0.status != nil && !LocalProxies.shared.isRunning($0.name) }
        work.async {
            LocalProxies.shared.stopAll()
            if helperTunnels { _ = try? HelperClient.call(HelperRequest(command: .downAll)) }
            DispatchQueue.main.async { self.refresh() }
        }
    }

    private func setBusy(_ name: String, _ value: Bool) {
        if value { busy.insert(name) } else { busy.remove(name) }
        changed()
    }

    // MARK: Library

    /// Imports config files (several at once); returns the added tunnels and per-file errors.
    func importFiles(_ urls: [URL]) -> (names: [String], errors: [String]) {
        var names: [String] = []
        var errors: [String] = []
        for url in urls {
            do { names += try TunnelLibrary.importFile(at: url).map(\.name) } catch {
                errors.append("\(url.lastPathComponent): \(error.localizedDescription)")
            }
        }
        refresh()
        return (names, errors)
    }

    /// Imports vless:// / trojan:// / hysteria2:// links or a base64 subscription.
    func importLinks(_ text: String) throws -> (names: [String], errors: [String]) {
        let result = try TunnelLibrary.importLinks(text)
        refresh()
        return (result.saved.map(\.name), result.errors)
    }

    /// Saves a new OpenConnect server; returns the tunnel's name.
    func addOpenConnect(_ config: OpenConnectConfig, name: String?) throws -> String {
        let saved = try TunnelLibrary.addOpenConnect(config, name: name)
        refresh()
        return saved.name
    }

    // MARK: Routing profiles

    var routingProfiles: [String] { RoutingProfiles.list() }

    /// Imports a routing profile (routing.json or a happ://routing link) from a file or the
    /// clipboard and downloads its geo files; calls `done` with the profile's name.
    func importRoutingProfile(fromClipboard: Bool, done: @escaping (String) -> Void = { _ in }) {
        NSApp.activate(ignoringOtherApps: true)
        let text: String
        if fromClipboard {
            text = NSPasteboard.general.string(forType: .string) ?? ""
        } else {
            let panel = NSOpenPanel()
            panel.title = String(localized: "Import Routing Profile")
            panel.message = String(localized: "A routing profile (routing.json) for VLESS, Trojan and Hysteria 2 tunnels")
            panel.prompt = String(localized: "Import")
            panel.allowedContentTypes = [.json, .plainText]
            guard panel.runModal() == .OK, let url = panel.url,
                  let contents = try? String(contentsOf: url, encoding: .utf8) else { return }
            text = contents
        }
        work.async {
            let result = Result { try RoutingProfiles.importProfile(text) }
            DispatchQueue.main.async {
                switch result {
                case .success(let name):
                    self.changed()
                    done(name)
                case .failure(let error):
                    Alerts.show(String(localized: "Could not import the routing profile"), error.localizedDescription)
                }
            }
        }
    }

    func updateRoutingProfile(_ name: String) {
        work.async {
            let result = Result { try RoutingProfiles.update(name) }
            DispatchQueue.main.async {
                if case .failure(let error) = result {
                    Alerts.show(String(localized: "Could not update “\(name)”"), error.localizedDescription)
                } else {
                    Alerts.info(String(localized: "“\(name)” updated"), String(localized: "The geo files were downloaded again. Reconnect tunnels that use it."))
                }
            }
        }
    }

    func removeRoutingProfile(_ name: String) -> Bool {
        guard Alerts.confirm(String(localized: "Remove routing profile “\(name)”?"),
                             String(localized: "Tunnels that use it go back to sending all traffic through the VPN."),
                             button: String(localized: "Remove"), destructive: true) else { return false }
        do { try RoutingProfiles.remove(name) } catch {
            Alerts.show(String(localized: "Could not remove “\(name)”"), error.localizedDescription)
            return false
        }
        changed()
        return true
    }

    func remove(_ name: String) {
        guard Alerts.confirm(String(localized: "Remove “\(name)”?"), String(localized: "The configuration and its saved passwords will be deleted. This can’t be undone."),
                             button: String(localized: "Remove"), destructive: true) else { return }
        userStopped.insert(name)
        if LocalProxies.shared.isRunning(name) {
            LocalProxies.shared.stop(name)
        } else if rows.first(where: { $0.name == name })?.status != nil {
            try? HelperClient.disconnect(name)
        }
        do { try TunnelLibrary.remove(name) } catch { Alerts.show(String(localized: "Could not remove “\(name)”"), error.localizedDescription) }
        refresh()
    }

    func forgetPassword(_ name: String) { Keychain.deleteAll(for: name) }

    func reveal(_ name: String) {
        if let saved = TunnelLibrary.find(name) { NSWorkspace.shared.activateFileViewerSelecting([saved.url]) }
    }

    func openTunnelsFolder() {
        try? FileManager.default.createDirectory(at: TunnelLibrary.directory, withIntermediateDirectories: true)
        NSWorkspace.shared.open(TunnelLibrary.directory)
    }

    func openLogs() { NSWorkspace.shared.open(URL(fileURLWithPath: "/var/log/bridge")) }

    // MARK: Helper

    func installHelper(then next: (() -> Void)? = nil) {
        installing = true
        changed()
        work.async {
            var failure: String?
            do { try HelperInstaller.install() } catch { failure = error.localizedDescription }
            // Pick up the new helper before continuing.
            let availability = HelperClient.availability(expectedBuild: Updater.currentBuild)
            DispatchQueue.main.async {
                self.installing = false
                self.helper = availability
                if let failure { Alerts.show(String(localized: "Helper installation failed"), failure) }
                self.refresh()
                if failure == nil, self.helperReady { next?() }
            }
        }
    }
}

enum Alerts {
    static func show(_ title: String, _ text: String) {
        _ = choose(title, text, buttons: [String(localized: "OK")], style: .warning)
    }

    static func info(_ title: String, _ text: String) {
        _ = choose(title, text, buttons: [String(localized: "OK")], style: .informational)
    }

    /// The main button, then Cancel. A destructive action gets a red button.
    static func confirm(_ title: String, _ text: String, button: String, destructive: Bool = false,
                        style: NSAlert.Style = .warning) -> Bool {
        choose(title, text, buttons: [button, String(localized: "Cancel")], style: style, destructive: destructive) == 0
    }

    /// Shows an alert and returns the index of the button pressed.
    @discardableResult
    static func choose(_ title: String, _ text: String, buttons: [String], style: NSAlert.Style = .informational,
                       destructive: Bool = false) -> Int {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        alert.alertStyle = style
        for button in buttons { alert.addButton(withTitle: button) }
        if destructive, let first = alert.buttons.first {
            first.hasDestructiveAction = true
            alert.buttons.last?.keyEquivalent = "\r"
            first.keyEquivalent = ""
        }
        return alert.runModal().rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
    }
}

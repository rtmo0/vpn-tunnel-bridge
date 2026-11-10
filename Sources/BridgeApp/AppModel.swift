import AppKit
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

        static func == (a: Row, b: Row) -> Bool {
            a.name == b.name && a.kind == b.kind && a.saved == b.saved
                && a.status?.state == b.status?.state && a.status?.connected == b.status?.connected
                && a.status?.rxBytes == b.status?.rxBytes && a.status?.txBytes == b.status?.txBytes
        }
    }

    private(set) var rows: [Row] = []
    private(set) var helper: HelperClient.Availability = .notInstalled
    private(set) var busy: Set<String> = []
    private(set) var installing = false
    private(set) var rates: [String: (rx: Double, tx: Double)] = [:]

    /// Called on the main thread whenever something visible changed.
    var onChange: () -> Void = {}

    private var lastCounters: [String: (rx: UInt64, tx: UInt64, at: Date)] = [:]
    private var refreshing = false
    private let work = DispatchQueue(label: "com.rtmo0.bridge.app.work", attributes: .concurrent)

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
            let availability = HelperClient.availability()
            var statuses: [TunnelStatus]?
            if case .ready = availability, !skipStatus { statuses = try? HelperClient.statuses() }
            DispatchQueue.main.async {
                self.refreshing = false
                let active = statuses ?? previous.compactMap(\.status)
                var rows = saved.map { entry in
                    Row(name: entry.name, kind: entry.kind, status: active.first { $0.name == entry.name }, saved: true)
                }
                for status in active where !rows.contains(where: { $0.name == status.name }) {
                    rows.append(Row(name: status.name, kind: status.kind, status: status, saved: false))
                }
                if case .ready = availability {} else {
                    rows = rows.map { Row(name: $0.name, kind: $0.kind, status: nil, saved: $0.saved) }
                }
                if statuses != nil { self.updateRates(rows) }
                let changed = rows != self.rows || availability != self.helper
                self.rows = rows
                self.helper = availability
                if changed || statuses != nil { self.changed() }
            }
        }
    }

    private func updateRates(_ rows: [Row]) {
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
        self.rates = rates
    }

    // MARK: Connect / disconnect

    func toggle(_ name: String) {
        guard !busy.contains(name) else { return }
        if rows.first(where: { $0.name == name })?.status != nil { disconnect(name) } else { connect(name) }
    }

    func connect(_ name: String) {
        guard helperReady else {
            Alerts.show("The Bridge helper is not installed", "Choose “Install Helper…” in the Bridge menu first.")
            return
        }
        let canOpenVPN = capabilities.contains(.openvpn)
        setBusy(name, true)
        work.async {
            var failure: String?
            do {
                let (text, kind) = try TunnelLibrary.load(name)
                if kind == .openvpn && !canOpenVPN {
                    throw ClientError("OpenVPN is not included in this build of Bridge.")
                }
                _ = try Connector.connect(name: name, text: text, kind: kind) { prompt in
                    DispatchQueue.main.sync { Prompter.ask(prompt) }
                }
            } catch let error as ClientError where error.description == "Cancelled" {
                failure = nil
            } catch {
                failure = error.localizedDescription
            }
            DispatchQueue.main.async {
                self.setBusy(name, false)
                if let failure { Alerts.show("Could not connect “\(name)”", failure) }
                self.refresh()
            }
        }
    }

    func disconnect(_ name: String) {
        setBusy(name, true)
        work.async {
            var failure: String?
            do { try HelperClient.disconnect(name) } catch { failure = error.localizedDescription }
            DispatchQueue.main.async {
                self.setBusy(name, false)
                if let failure { Alerts.show("Could not disconnect “\(name)”", failure) }
                self.refresh()
            }
        }
    }

    /// Disconnects and connects again, e.g. to apply new settings.
    func reconnect(_ name: String) {
        setBusy(name, true)
        work.async {
            try? HelperClient.disconnect(name)
            DispatchQueue.main.async {
                self.setBusy(name, false)
                self.connect(name)
            }
        }
    }

    func isActive(_ name: String) -> Bool { rows.first { $0.name == name }?.status != nil }

    func disconnectAll() {
        work.async {
            _ = try? HelperClient.call(HelperRequest(command: .downAll))
            DispatchQueue.main.async { self.refresh() }
        }
    }

    private func setBusy(_ name: String, _ value: Bool) {
        if value { busy.insert(name) } else { busy.remove(name) }
        changed()
    }

    // MARK: Library

    func importConfigs() {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSOpenPanel()
        panel.title = "Import Tunnels"
        panel.message = "WireGuard / AmneziaWG (.conf) or OpenVPN (.ovpn) files"
        panel.prompt = "Import"
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK else { return }
        var errors: [String] = []
        for url in panel.urls {
            do { try TunnelLibrary.importFile(at: url) } catch {
                errors.append("\(url.lastPathComponent): \(error.localizedDescription)")
            }
        }
        if !errors.isEmpty { Alerts.show("Some files could not be imported", errors.joined(separator: "\n")) }
        refresh()
    }

    func remove(_ name: String) {
        guard Alerts.confirm("Remove “\(name)”?", "The configuration and its saved passwords will be deleted.",
                             button: "Remove") else { return }
        if rows.first(where: { $0.name == name })?.status != nil { try? HelperClient.disconnect(name) }
        do { try TunnelLibrary.remove(name) } catch { Alerts.show("Could not remove “\(name)”", error.localizedDescription) }
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

    func installHelper() {
        installing = true
        changed()
        work.async {
            var failure: String?
            do { try HelperInstaller.install() } catch { failure = error.localizedDescription }
            DispatchQueue.main.async {
                self.installing = false
                if let failure { Alerts.show("Helper installation failed", failure) }
                self.refresh()
            }
        }
    }
}

enum Alerts {
    static func show(_ title: String, _ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        alert.alertStyle = .warning
        alert.runModal()
    }

    static func confirm(_ title: String, _ text: String, button: String) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        alert.addButton(withTitle: button)
        alert.addButton(withTitle: "Cancel")
        alert.alertStyle = .warning
        return alert.runModal() == .alertFirstButtonReturn
    }
}

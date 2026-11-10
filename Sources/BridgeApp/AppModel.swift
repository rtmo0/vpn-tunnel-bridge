import AppKit
import BridgeClient
import BridgeCore
import Foundation

@MainActor
final class AppModel: ObservableObject {
    struct Row: Identifiable, Equatable {
        var id: String { name }
        let name: String
        let kind: TunnelKind
        var status: TunnelStatus?
        var saved: Bool

        static func == (a: Row, b: Row) -> Bool {
            a.name == b.name && a.kind == b.kind && a.saved == b.saved
                && a.status?.state == b.status?.state && a.status?.rxBytes == b.status?.rxBytes
                && a.status?.txBytes == b.status?.txBytes && a.status?.connected == b.status?.connected
        }
    }

    @Published private(set) var rows: [Row] = []
    @Published private(set) var helper: HelperClient.Availability = .notInstalled
    @Published private(set) var busy: Set<String> = []
    @Published var message: String?
    @Published private(set) var installing = false

    private var timer: Timer?
    private var refreshing = false

    var anyConnected: Bool { rows.contains { $0.status?.connected == true } }
    var anyActive: Bool { rows.contains { $0.status != nil } }

    var helperReady: Bool {
        if case .ready = helper { return true }
        return false
    }

    var capabilities: [TunnelKind] {
        if case let .ready(capabilities) = helper { return capabilities }
        return []
    }

    init() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    func refresh() {
        guard !refreshing else { return }
        refreshing = true
        // While a connection attempt runs the helper is busy; keep the last known statuses.
        let skipStatus = !busy.isEmpty
        let previous = rows
        Task.detached {
            let saved = TunnelLibrary.list()
            let availability = HelperClient.availability()
            var statuses: [TunnelStatus]?
            if case .ready = availability, !skipStatus {
                statuses = try? HelperClient.statuses()
            }
            let fetched = statuses
            await MainActor.run {
                self.refreshing = false
                self.helper = availability
                let active = fetched ?? previous.compactMap(\.status)
                var rows = saved.map { entry in
                    Row(name: entry.name, kind: entry.kind, status: active.first { $0.name == entry.name }, saved: true)
                }
                for status in active where !rows.contains(where: { $0.name == status.name }) {
                    rows.append(Row(name: status.name, kind: status.kind, status: status, saved: false))
                }
                if case .ready = availability {} else {
                    rows = rows.map { Row(name: $0.name, kind: $0.kind, status: nil, saved: $0.saved) }
                }
                if rows != self.rows { self.rows = rows }
            }
        }
    }

    // MARK: Connect / disconnect

    func toggle(_ row: Row) {
        if row.status != nil { disconnect(row.name) } else { connect(row.name) }
    }

    func connect(_ name: String) {
        guard helperReady else {
            message = "Install the Bridge helper first."
            return
        }
        busy.insert(name)
        message = nil
        Task.detached {
            var failure: String?
            do {
                let (text, kind) = try TunnelLibrary.load(name)
                if kind == .openvpn, await !self.capabilities.contains(.openvpn) {
                    throw ClientError("OpenVPN is not included in this build of Bridge.")
                }
                _ = try Connector.connect(name: name, text: text, kind: kind) { prompt in
                    DispatchQueue.main.sync { MainActor.assumeIsolated { Prompter.ask(prompt) } }
                }
            } catch let error as ClientError where error.description == "Cancelled" {
                failure = nil
            } catch {
                failure = "\(name): \(error.localizedDescription)"
            }
            let failureMessage = failure
            await MainActor.run {
                self.busy.remove(name)
                if let failure = failureMessage { self.message = failure }
                self.refresh()
            }
        }
    }

    func disconnect(_ name: String) {
        busy.insert(name)
        Task.detached {
            var failure: String?
            do { try HelperClient.disconnect(name) } catch { failure = "\(name): \(error.localizedDescription)" }
            let failureMessage = failure
            await MainActor.run {
                self.busy.remove(name)
                if let failure = failureMessage { self.message = failure }
                self.refresh()
            }
        }
    }

    func disconnectAll() {
        Task.detached {
            _ = try? HelperClient.call(HelperRequest(command: .downAll))
            await MainActor.run { self.refresh() }
        }
    }

    // MARK: Library

    func importConfigs() {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSOpenPanel()
        panel.title = "Import VPN configuration"
        panel.message = "Choose WireGuard / AmneziaWG (.conf) or OpenVPN (.ovpn) files"
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.allowedContentTypes = []
        panel.allowsOtherFileTypes = true
        guard panel.runModal() == .OK else { return }
        var errors: [String] = []
        var imported: [String] = []
        for url in panel.urls {
            do {
                let saved = try TunnelLibrary.importFile(at: url)
                imported.append(saved.name)
            } catch {
                errors.append("\(url.lastPathComponent): \(error.localizedDescription)")
            }
        }
        message = errors.isEmpty ? nil : errors.joined(separator: "\n")
        refresh()
    }

    func remove(_ row: Row) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Remove “\(row.name)”?"
        alert.informativeText = "The configuration and its saved passwords will be deleted."
        alert.addButton(withTitle: "Remove")
        alert.addButton(withTitle: "Cancel")
        alert.alertStyle = .warning
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        if row.status != nil { try? HelperClient.disconnect(row.name) }
        do { try TunnelLibrary.remove(row.name) } catch { message = error.localizedDescription }
        refresh()
    }

    func forgetPasswords(_ row: Row) {
        Keychain.deleteAll(for: row.name)
    }

    func revealInFinder(_ row: Row) {
        if let saved = TunnelLibrary.find(row.name) {
            NSWorkspace.shared.activateFileViewerSelecting([saved.url])
        }
    }

    func openLogs() {
        NSWorkspace.shared.open(URL(fileURLWithPath: "/var/log/bridge"))
    }

    // MARK: Helper

    func installHelper() {
        installing = true
        message = nil
        Task.detached {
            var failure: String?
            do { try HelperInstaller.install() } catch { failure = error.localizedDescription }
            let failureMessage = failure
            await MainActor.run {
                self.installing = false
                if let failure = failureMessage { self.message = failure }
                self.refresh()
            }
        }
    }
}

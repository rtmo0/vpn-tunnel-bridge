import AppKit
import BridgeClient
import BridgeCore

/// The status item and its native menu, in the spirit of the WireGuard and
/// Shimo menus: status on top, tunnels you click to connect, then actions.
final class MenuController: NSObject, NSMenuDelegate {
    private let model: AppModel
    private let updater = Updater()
    private var updateItem: NSMenuItem?
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private var refreshTimer: Timer?
    private var animationTimer: Timer?
    private var animationFrame = 0
    private var menuIsOpen = false
    private var lastStructure = ""
    private var statusLineItem: NSMenuItem?
    private var detailItems: [String: NSMenuItem] = [:]
    private var busyItems: [NSMenuItem] = []

    /// Everything that changes which items exist (as opposed to their text).
    private var structure: String {
        let rows = model.rows.map { "\($0.name)|\($0.kind)|\($0.saved)|\($0.status?.connected ?? false)|\($0.status != nil)" }
        let holds = model.killSwitchHolds.joined(separator: ",")
        let update: String
        switch updater.state {
        case .idle, .checking: update = "none"
        case .available: update = "available"
        case .downloading: update = "downloading"
        case .installing: update = "installing"
        }
        return "\(rows)|\(model.busy.sorted())|\(model.helper)|\(model.installing)|\(update)|\(holds)"
    }

    init(model: AppModel) {
        self.model = model
        super.init()
        menu.delegate = self
        menu.autoenablesItems = false
        statusItem.menu = menu
        model.onChange = { [weak self] in self?.update() }
        updater.onChange = { [weak self] in self?.update() }
        update()
        model.refresh()
        updater.start()

        let timer = Timer(timeInterval: 2, repeats: true) { [weak self] _ in self?.model.refresh() }
        RunLoop.main.add(timer, forMode: .common)
        refreshTimer = timer
    }

    // MARK: Updates

    private func update() {
        updateIcon()
        let structure = self.structure
        if menuIsOpen && structure == lastStructure {
            // Only refresh text so open submenus stay open.
            statusLineItem?.title = statusLine
            updateItem?.title = updateTitle
            for row in model.rows {
                if let item = detailItems[row.name], let status = row.status {
                    item.attributedTitle = detailTitle(row, status)
                }
            }
        } else {
            lastStructure = structure
            rebuildMenu()
        }
    }

    private func updateIcon() {
        let state = model.iconState
        statusItem.button?.image = MenuBarIcon.image(state, frame: animationFrame)
        if state == .connecting {
            guard animationTimer == nil else { return }
            let timer = Timer(timeInterval: 0.35, repeats: true) { [weak self] _ in
                guard let self else { return }
                self.animationFrame += 1
                self.statusItem.button?.image = MenuBarIcon.image(self.model.iconState, frame: self.animationFrame)
                for item in self.busyItems { item.image = ProtocolIcon.loading(frame: self.animationFrame) }
            }
            RunLoop.main.add(timer, forMode: .common)
            animationTimer = timer
        } else {
            animationTimer?.invalidate()
            animationTimer = nil
            animationFrame = 0
        }
    }

    func menuWillOpen(_ menu: NSMenu) {
        menuIsOpen = true
        model.refresh()
    }

    func menuDidClose(_ menu: NSMenu) { menuIsOpen = false }

    // MARK: Menu

    private func rebuildMenu() {
        menu.removeAllItems()
        detailItems.removeAll()
        busyItems.removeAll()

        let status = info(statusLine)
        statusLineItem = status
        menu.addItem(status)

        if !model.killSwitchHolds.isEmpty {
            let item = action("Unblock Internet (Kill Switch)", #selector(releaseKillSwitch))
            item.image = NSImage(systemSymbolName: "exclamationmark.shield.fill", accessibilityDescription: nil)
            menu.addItem(item)
        }

        updateItem = nil
        switch updater.state {
        case .idle, .checking:
            break
        case .available:
            let item = action(updateTitle, #selector(installUpdate))
            item.image = NSImage(systemSymbolName: "arrow.down.circle.fill", accessibilityDescription: nil)
            updateItem = item
            menu.addItem(item)
        case .downloading, .installing:
            let item = info(updateTitle)
            updateItem = item
            menu.addItem(item)
        }
        if model.connectedRows.count == 1, let status = model.connectedRows.first?.status, !status.addresses.isEmpty {
            menu.addItem(info("Addresses: \(status.addresses.joined(separator: ", "))"))
        }

        switch model.helper {
        case .ready:
            break
        case .notInstalled, .outdated:
            menu.addItem(.separator())
            let title = model.installing ? "Installing Helper…"
                : (model.helper == .notInstalled ? "Install Helper…" : "Update Helper…")
            let item = action(title, #selector(installHelper))
            item.isEnabled = !model.installing
            menu.addItem(item)
        }

        menu.addItem(.separator())
        if model.rows.isEmpty {
            menu.addItem(info("No tunnels"))
        }
        for row in model.rows {
            menu.addItem(tunnelItem(row))
            if let status = row.status, status.connected {
                let detail = detailItem(row, status)
                detailItems[row.name] = detail
                menu.addItem(detail)
            }
        }

        menu.addItem(.separator())
        if model.rows.contains(where: { $0.status != nil }) {
            menu.addItem(action("Disconnect All", #selector(disconnectAll)))
        }
        menu.addItem(action("Import Tunnel(s) from File…", #selector(importConfigs), key: "o"))
        menu.addItem(action("Import Links from Clipboard", #selector(importFromClipboard), key: "V"))
        menu.addItem(action("Manage Tunnels…", #selector(manageTunnels), key: ","))

        menu.addItem(.separator())
        menu.addItem(action("Check for Updates…", #selector(checkUpdates)))
        menu.addItem(action("About Bridge", #selector(about)))
        menu.addItem(action("Quit Bridge", #selector(quit), key: "q"))
    }

    private var statusLine: String {
        let connected = model.connectedRows
        if !model.busy.isEmpty { return "Status: Connecting…" }
        if !model.killSwitchHolds.isEmpty && connected.isEmpty {
            return "Status: Kill switch is blocking traffic (\(model.killSwitchHolds.joined(separator: ", ")) dropped)"
        }
        if connected.count == 1 { return "Status: Connected — \(connected[0].name)" }
        if connected.count > 1 { return "Status: \(connected.count) tunnels connected" }
        if model.rows.contains(where: { $0.status != nil }) { return "Status: Waiting for server…" }
        switch model.helper {
        case .notInstalled: return "Status: Helper not installed"
        case .outdated: return "Status: Helper needs an update"
        case .ready: return "Status: Inactive"
        }
    }

    private func tunnelItem(_ row: AppModel.Row) -> NSMenuItem {
        let item = NSMenuItem(title: row.name, action: #selector(toggleTunnel(_:)), keyEquivalent: "")
        item.target = self
        item.representedObject = row.name
        item.image = ProtocolIcon.image(row.kind)
        item.toolTip = row.kind.displayName
        if model.busy.contains(row.name) || (row.status != nil && row.status?.connected == false) {
            item.image = ProtocolIcon.loading(frame: animationFrame)
            busyItems.append(item)
            item.state = .off
        } else if let status = row.status {
            item.state = status.connected ? .on : .mixed
        } else {
            item.state = .off
        }
        item.isEnabled = model.helperReady && (row.saved || row.status != nil) && !model.busy.contains(row.name)
        return item
    }

    /// Grey line under a connected tunnel: uptime and traffic.
    private func detailItem(_ row: AppModel.Row, _ status: TunnelStatus) -> NSMenuItem {
        let item = NSMenuItem()
        item.attributedTitle = detailTitle(row, status)
        item.indentationLevel = 2
        item.isEnabled = false
        if let server = status.server { item.toolTip = "Server: \(server)" }
        return item
    }

    private func detailTitle(_ row: AppModel.Row, _ status: TunnelStatus) -> NSAttributedString {
        var parts = [uptime(since: status.startedAt)]
        if let rate = model.rates[row.name] {
            parts.append("↓ \(Self.rate(rate.rx))  ↑ \(Self.rate(rate.tx))")
        } else {
            parts.append("↓ \(Self.bytes(status.rxBytes))  ↑ \(Self.bytes(status.txBytes))")
        }
        return NSAttributedString(string: parts.joined(separator: "   "), attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular),
            .foregroundColor: NSColor.secondaryLabelColor,
        ])
    }

    private func manageItem() -> NSMenuItem {
        let item = NSMenuItem(title: "Manage", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        sub.autoenablesItems = false
        sub.addItem(action("Open Tunnels Folder", #selector(openFolder)))
        sub.addItem(action("View Logs", #selector(openLogs)))
        let saved = model.rows.filter(\.saved)
        if !saved.isEmpty {
            sub.addItem(.separator())
            sub.addItem(namedSubmenu("Show in Finder", saved, #selector(reveal(_:))))
            let openVPN = saved.filter { $0.kind == .openvpn }
            if !openVPN.isEmpty { sub.addItem(namedSubmenu("Forget Password", openVPN, #selector(forget(_:)))) }
            sub.addItem(namedSubmenu("Remove Tunnel", saved, #selector(remove(_:))))
        }
        sub.addItem(.separator())
        sub.addItem(action("Reinstall Helper…", #selector(installHelper)))
        item.submenu = sub
        return item
    }

    private func namedSubmenu(_ title: String, _ rows: [AppModel.Row], _ selector: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        let sub = NSMenu()
        for row in rows {
            let entry = NSMenuItem(title: row.name, action: selector, keyEquivalent: "")
            entry.target = self
            entry.representedObject = row.name
            entry.image = ProtocolIcon.image(row.kind)
            sub.addItem(entry)
        }
        item.submenu = sub
        return item
    }

    private func info(_ title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    private func action(_ title: String, _ selector: Selector, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        item.target = self
        return item
    }

    // MARK: Formatting

    private func uptime(since date: Date) -> String {
        let s = max(0, Int(Date().timeIntervalSince(date)))
        return s >= 3600 ? String(format: "%d:%02d:%02d", s / 3600, s % 3600 / 60, s % 60)
            : String(format: "%02d:%02d", s / 60, s % 60)
    }

    private static func bytes(_ count: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .binary)
    }

    private static func rate(_ perSecond: Double) -> String {
        perSecond < 1 ? "0 KB/s" : ByteCountFormatter.string(fromByteCount: Int64(perSecond), countStyle: .binary) + "/s"
    }

    // MARK: Actions

    private func name(_ sender: Any?) -> String? { (sender as? NSMenuItem)?.representedObject as? String }

    @objc private func toggleTunnel(_ sender: Any?) { if let name = name(sender) { model.toggle(name) } }
    @objc private func disconnectAll() { model.disconnectAll() }
    @objc private func importConfigs() { model.importConfigs() }
    @objc private func importFromClipboard() { model.importFromClipboard() }
    @objc private func openFolder() { model.openTunnelsFolder() }
    @objc private func openLogs() { model.openLogs() }
    @objc private func reveal(_ sender: Any?) { if let name = name(sender) { model.reveal(name) } }
    @objc private func forget(_ sender: Any?) { if let name = name(sender) { model.forgetPassword(name) } }
    @objc private func remove(_ sender: Any?) { if let name = name(sender) { model.remove(name) } }
    @objc private func installHelper() { model.installHelper() }
    @objc private func manageTunnels() { ManageWindow.show(model: model) }
    @objc private func checkUpdates() { updater.check(userInitiated: true) }
    @objc private func releaseKillSwitch() { model.releaseKillSwitch() }
    @objc private func installUpdate() {
        if case let .available(release) = updater.state { updater.install(release) }
    }

    private var updateTitle: String {
        switch updater.state {
        case .idle, .checking: return ""
        case let .available(release): return "Update to Bridge \(release.version)…"
        case let .downloading(_, progress): return "Downloading update… \(Int(progress * 100))%"
        case .installing: return "Installing update…"
        }
    }

    @objc private func about() {
        NSApp.activate(ignoringOtherApps: true)
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: "Bridge",
            .applicationVersion: Updater.currentVersion,
            .version: "",
            .credits: Self.aboutCredits,
        ])
    }

    /// License block for the About panel, with a link to the repository.
    private static var aboutCredits: NSAttributedString {
        let center = NSMutableParagraphStyle()
        center.alignment = .center
        center.paragraphSpacing = 4
        let body: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11),
            .foregroundColor: NSColor.secondaryLabelColor,
            .paragraphStyle: center,
        ]
        let repo = "https://github.com/\(Updater.repository)"
        let text = NSMutableAttributedString()
        var protocols = body
        protocols[.font] = NSFont.systemFont(ofSize: 11, weight: .medium)
        protocols[.foregroundColor] = NSColor.labelColor
        text.append(NSAttributedString(string: "AmneziaWG · WireGuard · OpenVPN\n\n", attributes: protocols))
        text.append(NSAttributedString(string: "Free and open source under the MIT License.\n", attributes: body))
        text.append(NSAttributedString(
            string: "Use, copy, modify and distribute it freely; provided “as is”, without warranty.\n",
            attributes: body))
        var link = body
        link[.link] = URL(string: repo)!
        link[.foregroundColor] = NSColor.linkColor
        text.append(NSAttributedString(string: repo.replacingOccurrences(of: "https://", with: ""), attributes: link))
        text.append(NSAttributedString(
            string: "\n\nIncludes amneziawg-go (MIT) and OpenVPN (GPL-2.0).",
            attributes: body))
        return text
    }

    @objc private func quit() { NSApp.terminate(nil) }
}

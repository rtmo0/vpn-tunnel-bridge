import AppKit
import BridgeClient
import BridgeCore

/// The status item and its native menu: status on top, then anything the user
/// has to act on, then the tunnels you click to connect, then the windows.
final class MenuController: NSObject, NSMenuDelegate {
    private let model: AppModel
    private let updater = Updater()
    private var updateItem: NSMenuItem?
    // A fixed width: the glyph is always the same size, and a variable-length item is laid
    // out again on every image change, which makes it jitter while being ⌘-dragged.
    private let statusItem = NSStatusBar.system.statusItem(withLength: MenuBarIcon.size.width + 8)
    private let menu = NSMenu()
    private var refreshTimer: Timer?
    private var animationTimer: Timer?
    private var animationFrame = 0
    private var menuIsOpen = false
    private var lastStructure = ""
    private var statusLineItem: NSMenuItem?
    private var detailItems: [String: NSMenuItem] = [:]
    private var busyItems: [NSMenuItem] = []

    /// Where the right-hand column (state word and dot) of a tunnel item starts.
    private static let rightColumn: CGFloat = 250

    /// Everything that changes which items exist (as opposed to their text).
    private var structure: String {
        let rows = model.rows.map { "\($0.name)|\($0.kind)|\($0.saved)|\(model.phase(of: $0))" }
        let holds = model.killSwitchHolds.joined(separator: ",")
        let update: String
        switch updater.state {
        case .idle, .checking: update = "none"
        case .available: update = "available"
        case .downloading: update = "downloading"
        case .installing: update = "installing"
        }
        let details = UserDefaults.standard.bool(forKey: Preferences.showMenuDetails)
        return "\(rows)|\(model.helper)|\(model.installing)|\(update)|\(holds)|\(details)"
    }

    init(model: AppModel) {
        self.model = model
        super.init()
        menu.delegate = self
        menu.autoenablesItems = false
        statusItem.menu = menu
        SettingsWindow.updater = updater
        // Load the icon from the bundle ourselves: after an in-place update LaunchServices
        // may still hold a stale entry and hand alerts the generic white app icon.
        if let icon = Updater.bundleIcon { NSApp.applicationIconImage = icon }
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
            // Only refresh text so the open menu does not jump.
            if let item = statusLineItem { applyStatus(to: item) }
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

    /// Sets the glyph only when it actually changes (the status refresh runs every 2 s).
    private func setIcon(_ image: NSImage) {
        guard let button = statusItem.button, button.image !== image else { return }
        button.image = image
    }

    private func updateIcon() {
        let state = model.iconState
        setIcon(MenuBarIcon.image(state, frame: animationFrame))
        if state == .connecting {
            guard animationTimer == nil else { return }
            let timer = Timer(timeInterval: 0.35, repeats: true) { [weak self] _ in
                guard let self else { return }
                self.animationFrame += 1
                self.setIcon(MenuBarIcon.image(self.model.iconState, frame: self.animationFrame))
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

        let status = info("")
        applyStatus(to: status)
        statusLineItem = status
        menu.addItem(status)

        let actions = actionItems()
        if !actions.isEmpty {
            menu.addItem(.separator())
            actions.forEach(menu.addItem)
        }

        menu.addItem(.separator())
        if model.rows.isEmpty {
            menu.addItem(info(String(localized: "No tunnels yet")))
        }
        for row in model.rows {
            menu.addItem(tunnelItem(row))
            if let status = row.status, status.connected, UserDefaults.standard.bool(forKey: Preferences.showMenuDetails) {
                let detail = detailItem(row, status)
                detailItems[row.name] = detail
                menu.addItem(detail)
            }
        }

        menu.addItem(.separator())
        if model.rows.contains(where: { $0.status != nil }) {
            menu.addItem(action(String(localized: "Disconnect All"), #selector(disconnectAll)))
        }
        menu.addItem(action(String(localized: "Manage Tunnels…"), #selector(manageTunnels)))
        menu.addItem(action(String(localized: "Settings…"), #selector(openSettings), key: ","))

        menu.addItem(.separator())
        menu.addItem(action(String(localized: "Quit Bridge"), #selector(quit), key: "q"))
    }

    /// The things the user has to act on, each with a coloured symbol. Empty when all is well.
    private func actionItems() -> [NSMenuItem] {
        var items: [NSMenuItem] = []
        if !model.killSwitchHolds.isEmpty {
            items.append(action(String(localized: "Unblock Internet"), #selector(releaseKillSwitch),
                                symbol: "exclamationmark.shield.fill", color: Theme.critical))
        }
        switch model.helper {
        case .ready:
            break
        case .notInstalled, .outdated:
            let installed = model.helper != .notInstalled
            let title = model.installing ? String(localized: "Installing Helper…")
                : (installed ? String(localized: "Update Helper…") : String(localized: "Install Network Helper…"))
            let item = action(title, #selector(installHelper),
                              symbol: installed ? "arrow.triangle.2.circlepath.circle.fill" : "plus.circle.fill",
                              color: installed ? Theme.busy : Theme.accent)
            item.isEnabled = !model.installing
            items.append(item)
        }
        updateItem = nil
        switch updater.state {
        case .idle, .checking:
            break
        case .available:
            let item = action(updateTitle, #selector(installUpdate), symbol: "arrow.down.circle.fill", color: Theme.accent)
            updateItem = item
            items.append(item)
        case .downloading, .installing:
            let item = info(updateTitle)
            updateItem = item
            items.append(item)
        }
        if !model.rows.contains(where: \.saved) {
            items.append(action(String(localized: "Add Tunnel…"), #selector(addTunnel), symbol: "plus.square", color: .labelColor))
        }
        return items
    }

    private func applyStatus(to item: NSMenuItem) {
        let (text, alert) = statusLine
        if alert {
            item.attributedTitle = NSAttributedString(string: text, attributes: [
                .font: NSFont.menuFont(ofSize: 0).bold, .foregroundColor: NSColor.labelColor,
            ])
            item.image = Self.dot(Theme.critical)
            item.toolTip = String(localized: "Dropped: \(model.killSwitchHolds.joined(separator: ", "))")
        } else {
            item.attributedTitle = NSAttributedString(string: text, attributes: [
                .font: NSFont.menuFont(ofSize: 0), .foregroundColor: NSColor.secondaryLabelColor,
            ])
            item.image = nil
            item.toolTip = nil
        }
    }

    private var statusLine: (text: String, alert: Bool) {
        let connected = model.connectedRows
        if !model.killSwitchHolds.isEmpty && connected.isEmpty { return (String(localized: "Kill switch is blocking traffic"), true) }
        if !model.busy.isEmpty {
            let connecting = model.rows.contains { model.phase(of: $0) == .connecting }
            return (connecting ? String(localized: "Connecting…") : String(localized: "Disconnecting…"), false)
        }
        if connected.count == 1 { return (String(localized: "Connected — \(connected[0].name)"), false) }
        if connected.count > 1 { return (String(localized: "\(connected.count) tunnels connected"), false) }
        if model.rows.contains(where: { $0.status != nil }) { return (String(localized: "Waiting for server…"), false) }
        switch model.helper {
        case .notInstalled: return (String(localized: "Set up Bridge to connect"), false)
        case .outdated: return (String(localized: "The helper needs an update"), false)
        case .ready: return (String(localized: "Not connected"), false)
        }
    }

    private func tunnelItem(_ row: AppModel.Row) -> NSMenuItem {
        let phase = model.phase(of: row)
        let item = NSMenuItem(title: row.name, action: #selector(toggleTunnel(_:)), keyEquivalent: "")
        item.target = self
        item.representedObject = row.name
        item.attributedTitle = tunnelTitle(row.name, phase)
        item.state = phase == .connected ? .on : .off
        if phase.isBusy {
            item.image = ProtocolIcon.loading(frame: animationFrame)
            busyItems.append(item)
        } else {
            item.image = KindTile.menuImage(row.brand)
        }
        // Without the helper the click still works: connecting offers to install it first.
        // A tunnel the helper is still bringing up cannot be interrupted yet.
        item.isEnabled = (row.saved || row.status != nil) && !model.busy.contains(row.name)
        item.toolTip = phase == .waiting ? String(localized: "Click to disconnect") : row.brand.title
        return item
    }

    /// The name, and on the right the state word while busy plus the status dot.
    private func tunnelTitle(_ name: String, _ phase: TunnelPhase) -> NSAttributedString {
        let paragraph = NSMutableParagraphStyle()
        paragraph.tabStops = [NSTextTab(textAlignment: .right, location: Self.rightColumn)]
        let text = NSMutableAttributedString(string: name, attributes: [
            .font: NSFont.menuFont(ofSize: 0), .paragraphStyle: paragraph,
        ])
        guard let color = phase.nsColor else { return text }
        text.append(NSAttributedString(string: "\t"))
        if phase.isBusy {
            text.append(NSAttributedString(string: phase.title + "  ", attributes: [
                .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize),
                .foregroundColor: NSColor.secondaryLabelColor,
            ]))
        }
        text.append(NSAttributedString(string: "●", attributes: [
            .font: NSFont.menuFont(ofSize: 9), .foregroundColor: color, .baselineOffset: 1,
        ]))
        return text
    }

    /// Grey line under a connected tunnel: uptime, speed and address.
    private func detailItem(_ row: AppModel.Row, _ status: TunnelStatus) -> NSMenuItem {
        let item = NSMenuItem()
        item.attributedTitle = detailTitle(row, status)
        item.indentationLevel = 2
        item.isEnabled = false
        if let server = status.server { item.toolTip = String(localized: "Server: \(server)") }
        return item
    }

    private func detailTitle(_ row: AppModel.Row, _ status: TunnelStatus) -> NSAttributedString {
        var parts = [uptime(since: status.startedAt)]
        if let rate = model.rates[row.name] {
            parts.append("↓ \(Self.rate(rate.rx))  ↑ \(Self.rate(rate.tx))")
        } else {
            parts.append("↓ \(Self.bytes(status.rxBytes))  ↑ \(Self.bytes(status.txBytes))")
        }
        if let address = status.addresses.first {
            parts.append(address.split(separator: "/").first.map(String.init) ?? address)
        }
        return NSAttributedString(string: parts.joined(separator: " · "), attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular),
            .foregroundColor: NSColor.secondaryLabelColor,
        ])
    }

    private func info(_ title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    private func action(_ title: String, _ selector: Selector, key: String = "",
                        symbol: String? = nil, color: NSColor? = nil) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        item.target = self
        if let symbol, let color {
            let config = NSImage.SymbolConfiguration(pointSize: 13, weight: .regular)
                .applying(NSImage.SymbolConfiguration(hierarchicalColor: color))
            item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
                .withSymbolConfiguration(config)
        }
        return item
    }

    /// A small filled circle for the status line.
    private static func dot(_ color: NSColor) -> NSImage {
        let image = NSImage(size: NSSize(width: 12, height: 12), flipped: false) { _ in
            color.setFill()
            NSBezierPath(ovalIn: NSRect(x: 3, y: 3, width: 7, height: 7)).fill()
            return true
        }
        image.isTemplate = false
        return image
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
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowedUnits = [.useKB, .useMB, .useGB]
        return formatter.string(fromByteCount: Int64(max(0, perSecond))) + "/s"
    }

    // MARK: Actions

    private func name(_ sender: Any?) -> String? { (sender as? NSMenuItem)?.representedObject as? String }

    @objc private func toggleTunnel(_ sender: Any?) { if let name = name(sender) { model.toggle(name) } }
    @objc private func disconnectAll() { model.disconnectAll() }
    @objc private func installHelper() { model.installHelper() }
    @objc private func manageTunnels() { ManageWindow.show(model: model) }
    @objc private func addTunnel() { ManageWindow.show(model: model, addTunnel: true) }
    @objc private func openSettings() { SettingsWindow.show(model: model) }
    @objc private func releaseKillSwitch() { model.releaseKillSwitch() }
    @objc private func installUpdate() {
        if case let .available(release) = updater.state { updater.install(release) }
    }

    private var updateTitle: String {
        switch updater.state {
        case .idle, .checking: return ""
        case let .available(release): return String(localized: "Update to Bridge \(release.version)…")
        case let .downloading(_, progress): return String(localized: "Downloading update… \(Int(progress * 100))%")
        case .installing: return String(localized: "Installing update…")
        }
    }

    @objc private func quit() { NSApp.terminate(nil) }
}

private extension NSFont {
    var bold: NSFont { NSFontManager.shared.convert(self, toHaveTrait: .boldFontMask) }
}

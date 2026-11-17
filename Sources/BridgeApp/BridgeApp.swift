import AppKit

/// Bridge is a menu bar app: no Dock icon, no windows, just a native menu.
@main
enum BridgeApp {
    private static var controller: MenuController?

    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        Preferences.register()
        app.mainMenu = editMenu()
        controller = MenuController(model: AppModel())
        app.run()
    }

    /// A menu bar app has no visible main menu, but text fields find ⌘X/⌘C/⌘V/⌘A/⌘Z
    /// through the main menu's key equivalents: give it an Edit menu that is never shown.
    private static func editMenu() -> NSMenu {
        let main = NSMenu()
        let item = NSMenuItem()
        main.addItem(item)
        let edit = NSMenu(title: String(localized: "Edit"))
        func add(_ title: String, _ action: String, _ key: String, _ modifiers: NSEvent.ModifierFlags = .command) {
            let entry = NSMenuItem(title: title, action: Selector(action), keyEquivalent: key)
            entry.keyEquivalentModifierMask = modifiers
            edit.addItem(entry)
        }
        add(String(localized: "Undo"), "undo:", "z")
        add(String(localized: "Redo"), "redo:", "z", [.command, .shift])
        edit.addItem(.separator())
        add(String(localized: "Cut"), "cut:", "x")
        add(String(localized: "Copy"), "copy:", "c")
        add(String(localized: "Paste"), "paste:", "v")
        add(String(localized: "Select All"), "selectAll:", "a")
        item.submenu = edit
        return main
    }
}

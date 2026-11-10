import AppKit

/// Bridge is a menu bar app: no Dock icon, no windows, just a native menu.
@main
enum BridgeApp {
    private static var controller: MenuController?

    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        controller = MenuController(model: AppModel())
        app.run()
    }
}

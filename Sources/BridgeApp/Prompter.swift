import AppKit
import BridgeClient

/// One layout for every sign-in dialog: an optional red error line, then a grid of
/// right-aligned labels and 240 pt fields, then String(localized: "Remember in Keychain"). The main
/// button stays disabled while a required field is empty.
final class LoginForm: NSObject, NSTextFieldDelegate {
    let alert = NSAlert()
    private let grid = NSGridView()
    private var required: [NSTextField] = []
    private var firstEmpty: NSView?
    private let error: String?

    init(title: String, message: String?, error: String?, button: String) {
        self.error = error
        super.init()
        NSApp.activate(ignoringOtherApps: true)
        alert.messageText = title
        alert.informativeText = message ?? ""
        if let error, !error.isEmpty { alert.alertStyle = .warning }
        alert.addButton(withTitle: button)
        alert.addButton(withTitle: String(localized: "Cancel"))
        grid.rowSpacing = 8
        grid.columnSpacing = 8
    }

    @discardableResult
    func field(_ label: String, value: String = "", placeholder: String? = nil, secure: Bool = false,
               required isRequired: Bool = true) -> NSTextField {
        let field: NSTextField = secure ? NSSecureTextField() : NSTextField()
        field.stringValue = value
        field.placeholderString = placeholder
        field.delegate = self
        field.translatesAutoresizingMaskIntoConstraints = false
        field.widthAnchor.constraint(equalToConstant: 240).isActive = true
        if isRequired { required.append(field) }
        if value.isEmpty && firstEmpty == nil { firstEmpty = field }
        grid.addRow(with: [makeLabel(label), field])
        return field
    }

    func popup(_ label: String, options: [(value: String, title: String)], selected: String?) -> NSPopUpButton {
        let popup = NSPopUpButton()
        for option in options {
            popup.addItem(withTitle: option.title)
            popup.lastItem?.representedObject = option.value
        }
        if let selected, let index = options.firstIndex(where: { $0.value == selected }) { popup.selectItem(at: index) }
        grid.addRow(with: [makeLabel(label), popup])
        return popup
    }

    func remember(_ title: String = String(localized: "Remember in Keychain")) -> NSButton {
        let box = NSButton(checkboxWithTitle: title, target: nil, action: nil)
        box.state = .on
        grid.addRow(with: [NSGridCell.emptyContentView, box])
        return box
    }

    /// Shows the dialog; true when the main button was pressed.
    func run() -> Bool {
        if let error, !error.isEmpty {
            let label = NSTextField(wrappingLabelWithString: error)
            label.textColor = .systemRed
            label.font = .systemFont(ofSize: NSFont.smallSystemFontSize, weight: .medium)
            label.preferredMaxLayoutWidth = 320
            let row = grid.insertRow(at: 0, with: [label])
            if grid.numberOfColumns > 1 { row.mergeCells(in: NSRange(location: 0, length: grid.numberOfColumns)) }
            row.cell(at: 0).xPlacement = .leading
            row.bottomPadding = 4
        }
        if grid.numberOfRows > 0 {
            if grid.numberOfColumns > 1 { grid.column(at: 0).xPlacement = .trailing }
            grid.layoutSubtreeIfNeeded()
            grid.frame.size = grid.fittingSize
            alert.accessoryView = grid
        }
        alert.layout()
        updateButton()
        if let firstEmpty { alert.window.initialFirstResponder = firstEmpty }
        return alert.runModal() == .alertFirstButtonReturn
    }

    func controlTextDidChange(_ notification: Notification) { updateButton() }

    private func updateButton() {
        alert.buttons.first?.isEnabled = required.allSatisfy { !$0.stringValue.isEmpty }
    }

    private func makeLabel(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.alignment = .right
        return label
    }
}

/// Native dialogs for credentials, passphrases and one-time codes.
enum Prompter {
    static func ask(_ prompt: SecretPrompt) -> SecretAnswer? {
        switch prompt {
        case let .usernamePassword(tunnel, username, retry):
            let form = LoginForm(title: String(localized: "Sign in to “\(tunnel)”"),
                                 message: String(localized: "This VPN server needs a username and password."),
                                 error: retry ? String(localized: "Wrong username or password. Try again.") : nil, button: String(localized: "Connect"))
            let user = form.field(String(localized: "Username"), value: username ?? "")
            let pass = form.field(String(localized: "Password"), secure: true)
            let remember = form.remember()
            if !(username ?? "").isEmpty { form.alert.window.initialFirstResponder = pass }
            guard form.run() else { return nil }
            return SecretAnswer(username: user.stringValue, secret: pass.stringValue, remember: remember.state == .on)

        case let .keyPassphrase(tunnel, retry):
            let form = LoginForm(title: String(localized: "Unlock the key of “\(tunnel)”"),
                                 message: String(localized: "The private key is protected by a passphrase."),
                                 error: retry ? String(localized: "Wrong passphrase. Try again.") : nil, button: String(localized: "Connect"))
            let pass = form.field(String(localized: "Passphrase"), secure: true)
            let remember = form.remember()
            guard form.run() else { return nil }
            return SecretAnswer(secret: pass.stringValue, remember: remember.state == .on)

        case let .challenge(tunnel, text, echo):
            let form = LoginForm(title: String(localized: "Verification for “\(tunnel)”"), message: text, error: nil, button: String(localized: "Connect"))
            let code = form.field(String(localized: "Code"), placeholder: String(localized: "One-time code"), secure: !echo)
            guard form.run() else { return nil }
            return SecretAnswer(secret: code.stringValue, remember: false)
        }
    }
}

/// Installs or updates the privileged helper with an administrator prompt.
enum HelperInstaller {
    struct Failure: Error, LocalizedError {
        let errorDescription: String?
    }

    static func install() throws {
        guard let resources = Bundle.main.resourceURL else { throw Failure(errorDescription: "App resources not found") }
        let script = resources.appendingPathComponent("install-helper.sh").path
        guard FileManager.default.isExecutableFile(atPath: script) else {
            throw Failure(errorDescription: "install-helper.sh is missing from the app bundle")
        }
        func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        func appleScriptQuote(_ s: String) -> String {
            "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        let version = Updater.currentBuild
        let command = "\(shellQuote(script)) \(shellQuote(resources.path)) \(shellQuote(version))"
        let source = "do shell script \(appleScriptQuote(command)) with prompt "
            + "\"Bridge needs to install its network helper.\" with administrator privileges"

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", source]
        let pipe = Pipe()
        process.standardError = pipe
        process.standardOutput = pipe
        try process.run()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            if output.contains("-128") { return }  // user cancelled
            throw Failure(errorDescription: "Helper installation failed: "
                + output.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
}

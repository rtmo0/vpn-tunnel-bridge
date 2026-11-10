import AppKit
import BridgeClient

/// Native dialogs for credentials, passphrases and one-time codes.

enum Prompter {
    static func ask(_ prompt: SecretPrompt) -> SecretAnswer? {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.addButton(withTitle: "Connect")
        alert.addButton(withTitle: "Cancel")

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.frame = NSRect(x: 0, y: 0, width: 280, height: 10)

        func field(_ placeholder: String, secure: Bool, value: String = "") -> NSTextField {
            let f: NSTextField = secure ? NSSecureTextField() : NSTextField()
            f.placeholderString = placeholder
            f.stringValue = value
            f.translatesAutoresizingMaskIntoConstraints = false
            f.widthAnchor.constraint(equalToConstant: 280).isActive = true
            stack.addArrangedSubview(f)
            return f
        }
        func checkbox() -> NSButton {
            let box = NSButton(checkboxWithTitle: "Remember in Keychain", target: nil, action: nil)
            box.state = .on
            stack.addArrangedSubview(box)
            return box
        }

        switch prompt {
        case let .usernamePassword(tunnel, username, retry):
            alert.messageText = retry ? "Sign-in to “\(tunnel)” failed" : "Sign in to “\(tunnel)”"
            alert.informativeText = retry ? "Check your username and password and try again."
                : "This VPN server needs a username and password."
            if retry { alert.alertStyle = .warning }
            let user = field("Username", secure: false, value: username ?? "")
            let pass = field("Password", secure: true)
            let remember = checkbox()
            stack.layoutSubtreeIfNeeded()
            stack.frame.size = stack.fittingSize
            alert.accessoryView = stack
            alert.window.initialFirstResponder = (username ?? "").isEmpty ? user : pass
            guard alert.runModal() == .alertFirstButtonReturn, !user.stringValue.isEmpty else { return nil }
            return SecretAnswer(username: user.stringValue, secret: pass.stringValue, remember: remember.state == .on)

        case let .keyPassphrase(tunnel, retry):
            alert.messageText = retry ? "Wrong passphrase" : "Private key passphrase"
            alert.informativeText = "The private key of “\(tunnel)” is protected by a passphrase."
            let pass = field("Passphrase", secure: true)
            let remember = checkbox()
            stack.layoutSubtreeIfNeeded()
            stack.frame.size = stack.fittingSize
            alert.accessoryView = stack
            alert.window.initialFirstResponder = pass
            guard alert.runModal() == .alertFirstButtonReturn, !pass.stringValue.isEmpty else { return nil }
            return SecretAnswer(secret: pass.stringValue, remember: remember.state == .on)

        case let .challenge(tunnel, text, echo):
            alert.messageText = "Verification for “\(tunnel)”"
            alert.informativeText = text
            let code = field("Code", secure: !echo)
            stack.layoutSubtreeIfNeeded()
            stack.frame.size = stack.fittingSize
            alert.accessoryView = stack
            alert.window.initialFirstResponder = code
            guard alert.runModal() == .alertFirstButtonReturn, !code.stringValue.isEmpty else { return nil }
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

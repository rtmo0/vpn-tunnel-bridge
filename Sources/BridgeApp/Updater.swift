import AppKit
import CryptoKit
import Foundation

/// Self-update from GitHub Releases.
///
/// CI publishes `Bridge.zip` and `Bridge.zip.sha256` for every `v*` tag. The app
/// checks the latest release, downloads the zip, verifies the checksum and the
/// bundle, swaps itself in place and relaunches.
final class Updater: NSObject, URLSessionDownloadDelegate {
    struct Release {
        let version: String
        let notes: String
        let zipURL: URL
        let checksumURL: URL?
        let page: URL
    }

    enum State {
        case idle
        case checking
        case available(Release)
        case downloading(Release, progress: Double)
        case installing
    }

    private(set) var state: State = .idle { didSet { DispatchQueue.main.async { self.onChange() } } }
    var onChange: () -> Void = {}

    static var repository: String {
        Bundle.main.object(forInfoDictionaryKey: "BridgeUpdateRepository") as? String ?? "rtmo0/vpn-tunnel-bridge"
    }

    static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    }

    private var timer: Timer?
    private var session: URLSession?
    private var pending: Release?

    func start() {
        check(userInitiated: false)
        let timer = Timer(timeInterval: 6 * 3600, repeats: true) { [weak self] _ in
            self?.check(userInitiated: false)
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    // MARK: Check

    func check(userInitiated: Bool) {
        if case .downloading = state { return }
        if case .installing = state { return }
        state = .checking
        var request = URLRequest(url: URL(string: "https://api.github.com/repos/\(Self.repository)/releases/latest")!)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Bridge-Updater", forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 20
        URLSession.shared.dataTask(with: request) { data, response, error in
            let release = data.flatMap(Self.parse)
            DispatchQueue.main.async {
                guard let release else {
                    self.state = .idle
                    if userInitiated {
                        let reason = error?.localizedDescription
                            ?? ((response as? HTTPURLResponse)?.statusCode == 404 ? "No releases published yet." : "Unexpected response.")
                        Alerts.show("Could not check for updates", reason)
                    }
                    return
                }
                if Self.isNewer(release.version, than: Self.currentVersion) {
                    self.state = .available(release)
                    if userInitiated { self.install(release) }
                } else {
                    self.state = .idle
                    if userInitiated {
                        Alerts.info("Bridge is up to date", "Version \(Self.currentVersion) is the latest.")
                    }
                }
            }
        }.resume()
    }

    private static func parse(_ data: Data) -> Release? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = json["tag_name"] as? String,
              (json["draft"] as? Bool) != true, (json["prerelease"] as? Bool) != true,
              let assets = json["assets"] as? [[String: Any]] else { return nil }
        func asset(_ name: String) -> URL? {
            assets.first { $0["name"] as? String == name }
                .flatMap { $0["browser_download_url"] as? String }
                .flatMap(URL.init(string:))
        }
        guard let zip = asset("Bridge.zip") else { return nil }
        let page = (json["html_url"] as? String).flatMap(URL.init(string:))
            ?? URL(string: "https://github.com/\(repository)/releases")!
        return Release(version: tag.hasPrefix("v") ? String(tag.dropFirst()) : tag,
                       notes: (json["body"] as? String) ?? "", zipURL: zip,
                       checksumURL: asset("Bridge.zip.sha256"), page: page)
    }

    static func isNewer(_ candidate: String, than current: String) -> Bool {
        func parts(_ v: String) -> [Int] {
            v.split(whereSeparator: { $0 == "." || $0 == "-" }).map { Int($0) ?? 0 }
        }
        let a = parts(candidate), b = parts(current)
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }

    // MARK: Install

    func install(_ release: Release) {
        let notes = release.notes.trimmingCharacters(in: .whitespacesAndNewlines)
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Bridge \(release.version) is available"
        alert.informativeText = "You have \(Self.currentVersion). Bridge will download the update, restart, "
            + "and keep your tunnels connected.\n\n" + (notes.isEmpty ? "" : String(notes.prefix(600)))
        alert.addButton(withTitle: "Install and Restart")
        alert.addButton(withTitle: "Later")
        alert.addButton(withTitle: "Release Notes")
        switch alert.runModal() {
        case .alertFirstButtonReturn: download(release)
        case .alertThirdButtonReturn: NSWorkspace.shared.open(release.page)
        default: break
        }
    }

    private func download(_ release: Release) {
        pending = release
        state = .downloading(release, progress: 0)
        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        self.session = session
        session.downloadTask(with: release.zipURL).resume()
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64,
                    totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        guard let release = pending, totalBytesExpectedToWrite > 0 else { return }
        let progress = Double(totalBytesWritten) / Double(totalBytesExpectedToWrite)
        DispatchQueue.main.async { self.state = .downloading(release, progress: progress) }
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        // The temporary file disappears when this method returns: move it first.
        let zip = FileManager.default.temporaryDirectory.appendingPathComponent("Bridge-update-\(UUID().uuidString).zip")
        do {
            try FileManager.default.moveItem(at: location, to: zip)
        } catch {
            fail("Could not save the download: \(error.localizedDescription)")
            return
        }
        guard let release = pending else { return }
        DispatchQueue.global().async { self.verifyAndInstall(zip: zip, release: release) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { fail("Download failed: \(error.localizedDescription)") }
        session.finishTasksAndInvalidate()
    }

    private func fail(_ message: String) {
        DispatchQueue.main.async {
            if let release = self.pending { self.state = .available(release) } else { self.state = .idle }
            self.pending = nil
            Alerts.show("Update failed", message)
        }
    }

    private func verifyAndInstall(zip: URL, release: Release) {
        do {
            if let checksumURL = release.checksumURL {
                let expected = String(decoding: try Data(contentsOf: checksumURL), as: UTF8.self)
                    .split(whereSeparator: \.isWhitespace).first.map(String.init)?.lowercased() ?? ""
                let actual = SHA256.hash(data: try Data(contentsOf: zip)).map { String(format: "%02x", $0) }.joined()
                guard expected == actual else { throw UpdateError("Checksum mismatch: the download is corrupted.") }
            }

            let staging = FileManager.default.temporaryDirectory.appendingPathComponent("Bridge-update-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
            try run("/usr/bin/ditto", ["-x", "-k", zip.path, staging.path])
            let newApp = staging.appendingPathComponent("Bridge.app")
            guard let bundle = Bundle(url: newApp),
                  bundle.bundleIdentifier == Bundle.main.bundleIdentifier else {
                throw UpdateError("The downloaded archive does not contain Bridge.")
            }
            try run("/usr/bin/codesign", ["--verify", "--deep", newApp.path])
            DispatchQueue.main.async {
                self.state = .installing
                self.replaceAndRelaunch(with: newApp)
            }
        } catch {
            fail("\(error)")
        }
    }

    /// A detached shell waits for this process to exit, swaps the bundle and reopens it.
    private func replaceAndRelaunch(with newApp: URL) {
        let current = Bundle.main.bundleURL
        func q(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let script = """
        while /bin/kill -0 \(ProcessInfo.processInfo.processIdentifier) 2>/dev/null; do /bin/sleep 0.2; done
        /bin/rm -rf \(q(current.path)) && /usr/bin/ditto \(q(newApp.path)) \(q(current.path)) \
          && /usr/bin/xattr -dr com.apple.quarantine \(q(current.path)) 2>/dev/null; /usr/bin/open \(q(current.path))
        """
        let writable = FileManager.default.isWritableFile(atPath: current.deletingLastPathComponent().path)
        let process = Process()
        if writable {
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", script]
        } else {
            let escaped = script.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", "do shell script \"\(escaped)\" with administrator privileges"]
        }
        do {
            try process.run()
        } catch {
            fail("Could not start the installer: \(error.localizedDescription)")
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { NSApp.terminate(nil) }
    }

    private func run(_ path: String, _ args: [String]) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardError = pipe
        p.standardOutput = pipe
        try p.run()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else {
            let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            throw UpdateError("\(URL(fileURLWithPath: path).lastPathComponent) failed: \(out)")
        }
    }
}

struct UpdateError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

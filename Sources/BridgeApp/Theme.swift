import AppKit
import SwiftUI

/// One vocabulary for a tunnel's state, shared by the menu, the sidebar and the
/// detail header, so the same state always has the same word and colour.
enum TunnelPhase: Equatable {
    case off
    case connecting
    /// The helper brought the tunnel up but the server has not answered yet.
    case waiting
    case connected
    case disconnecting

    var title: String {
        switch self {
        case .off: String(localized: "Off")
        case .connecting: String(localized: "Connecting…")
        case .waiting: String(localized: "Waiting for server…")
        case .connected: String(localized: "Connected")
        case .disconnecting: String(localized: "Disconnecting…")
        }
    }

    /// Status dot colour; nil when the tunnel is off (no dot).
    var nsColor: NSColor? {
        switch self {
        case .off: nil
        case .connected: Theme.good
        case .connecting, .waiting, .disconnecting: Theme.busy
        }
    }

    var color: Color? { nsColor.map(Color.init(nsColor:)) }

    var isBusy: Bool { self == .connecting || self == .waiting || self == .disconnecting }
}

enum Theme {
    static let good = NSColor.systemGreen
    static let busy = NSColor.systemOrange
    static let critical = NSColor.systemRed
    static let accent = NSColor.controlAccentColor
}

/// Number and time formatting shared by the menu and the windows.
enum Format {
    static func uptime(since date: Date, now: Date = Date()) -> String {
        let s = max(0, Int(now.timeIntervalSince(date)))
        return s >= 3600 ? String(format: "%d:%02d:%02d", s / 3600, s % 3600 / 60, s % 60)
            : String(format: "%02d:%02d", s / 60, s % 60)
    }

    static func bytes(_ count: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .binary)
    }

    /// Speed in KB/s or larger, so small rates never read "512 bytes/s".
    static func rate(_ perSecond: Double) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowedUnits = [.useKB, .useMB, .useGB]
        return formatter.string(fromByteCount: Int64(max(0, perSecond))) + "/s"
    }

    static func ago(_ date: Date) -> String {
        let s = max(0, Int(Date().timeIntervalSince(date)))
        return s < 60 ? String(localized: "\(s) s ago") : String(localized: "\(s / 60) min ago")
    }
}

extension AppModel {
    func phase(of row: Row) -> TunnelPhase {
        if busy.contains(row.name) { return row.status == nil ? .connecting : .disconnecting }
        guard let status = row.status else { return .off }
        return status.connected ? .connected : .waiting
    }
}

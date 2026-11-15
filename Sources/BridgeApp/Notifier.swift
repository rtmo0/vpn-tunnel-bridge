import Foundation
import UserNotifications

/// System notifications for things that happen without the user doing anything,
/// such as a tunnel dropping. Errors of actions the user started stay alerts.
enum Notifier {
    static func post(_ title: String, _ body: String) {
        // UNUserNotificationCenter needs a real app bundle; `swift run` has none.
        guard Bundle.main.bundleIdentifier != nil else { return }
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
    }
}

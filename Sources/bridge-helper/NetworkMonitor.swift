import Foundation
import SystemConfiguration

/// Calls `onChange` (debounced) when the Mac's primary network changes:
/// Wi-Fi to Ethernet, another Wi-Fi network, sleep/wake with a new lease, …
final class NetworkMonitor {
    private var store: SCDynamicStore?
    private let queue = DispatchQueue(label: "com.rtmo0.bridge.helper.network")
    private var pending: DispatchWorkItem?
    private let onChange: () -> Void

    init(onChange: @escaping () -> Void) {
        self.onChange = onChange
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                            retain: nil, release: nil, copyDescription: nil)
        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info else { return }
            Unmanaged<NetworkMonitor>.fromOpaque(info).takeUnretainedValue().changed()
        }
        guard let store = SCDynamicStoreCreate(nil, "com.rtmo0.bridge.helper.network" as CFString, callback, &context)
        else { return }
        let keys = ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"] as CFArray
        SCDynamicStoreSetNotificationKeys(store, keys, nil)
        SCDynamicStoreSetDispatchQueue(store, queue)
        self.store = store
    }

    private func changed() {
        // Interfaces flap while switching networks; act once things settle.
        pending?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.onChange() }
        pending = work
        queue.asyncAfter(deadline: .now() + 2, execute: work)
    }
}

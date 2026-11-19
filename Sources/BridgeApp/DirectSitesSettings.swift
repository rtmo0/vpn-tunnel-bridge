import BridgeClient
import BridgeCore
import SwiftUI

/// Settings → Direct Sites: sites that go through Wi-Fi or Ethernet while a tunnel
/// takes all traffic. Stored for the app and the CLI; the helper gets the list with
/// every connection and at once when it changes here.
struct DirectSitesSettings: View {
    @EnvironmentObject var model: AppModel
    @State private var stored = DirectSitesStore.load()
    @State private var text = ""
    @State private var error: String?
    @State private var applying = false
    @State private var loaded = false

    private var draft: [String] { TunnelDetail.split(text) }
    private var changed: Bool { draft != stored.domains }

    var body: some View {
        Form {
            Section {
                Toggle("Send these sites direct while a tunnel takes all traffic", isOn: Binding(
                    get: { stored.enabled },
                    set: { on in save(DirectSitesStore.Settings(enabled: on, domains: stored.domains)) }))
                VStack(alignment: .leading, spacing: 6) {
                    TextField("Sites", text: $text, prompt: Text("gosuslugi.ru\nnalog.gov.ru"), axis: .vertical)
                        .labelsHidden()
                        .textFieldStyle(.roundedBorder)
                        .font(.callout.monospaced())
                        .lineLimit(4...10)
                    HStack {
                        Text("One per line or separated by commas. Subdomains are included in DNS.")
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("Revert") { text = stored.domains.joined(separator: "\n"); error = nil }
                            .disabled(!changed || applying)
                        Button("Save") { save(DirectSitesStore.Settings(enabled: stored.enabled, domains: draft)) }
                            .keyboardShortcut(.defaultAction)
                            .disabled(!changed || applying)
                    }
                    if let error {
                        Label(error, systemImage: "exclamationmark.circle.fill").font(.caption).foregroundStyle(.red)
                    }
                }
            } header: {
                Text("Direct sites")
            } footer: {
                Text("Bridge looks these sites up through your Wi-Fi or Ethernet DNS and routes their addresses around the VPN. It works for tunnels that take all traffic and is best effort: a site may also use addresses its name does not return (CDNs, DNS over HTTPS in the browser), and another site sharing an address goes direct too. Off while a tunnel's kill switch is on.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            let active = model.rows.compactMap(\.status).filter { $0.directSites != nil }
            if !active.isEmpty {
                ForEach(active, id: \.name) { status in
                    Section(String(localized: "Now around “\(status.name)”")) {
                        DirectSitesStatusList(sites: status.directSites ?? [])
                    }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear {
            guard !loaded else { return }
            stored = DirectSitesStore.load()
            text = stored.domains.joined(separator: "\n")
            loaded = true
        }
    }

    private func save(_ next: DirectSitesStore.Settings) {
        do {
            let saved = try DirectSitesStore.save(next)
            stored = saved
            text = saved.domains.joined(separator: "\n")
            error = nil
        } catch let failure as ConfigError {
            error = failure.message
            return
        } catch {
            self.error = "\(error)"
            return
        }
        guard case .ready = model.helper, model.rows.contains(where: { $0.status != nil }) else { return }
        applying = true
        let domains = stored.active
        Task {
            let failure: String? = await Task.detached { () -> String? in
                do {
                    try HelperClient.setDirectSites(domains)
                    return nil
                } catch let error as ClientError where error.description == "Cancelled" {
                    return nil
                } catch {
                    return "\(error)"
                }
            }.value
            if let failure { error = failure }
            applying = false
            model.refresh()
        }
    }
}

/// One line per direct site: how many of its addresses go around the VPN.
struct DirectSitesStatusList: View {
    let sites: [DirectSiteStatus]

    var body: some View {
        ForEach(sites, id: \.domain) { site in
            LabeledContent {
                Text(detail(site)).foregroundStyle(site.unresolved || site.addresses == 0 ? .orange : .secondary)
            } label: {
                Text(site.domain).font(.callout.monospaced()).textSelection(.enabled)
            }
        }
    }

    private func detail(_ site: DirectSiteStatus) -> String {
        var text: String
        if site.addresses > 0 {
            text = String(localized: "\(site.addresses) address(es) direct")
        } else if site.unresolved {
            text = String(localized: "Not found in DNS")
        } else {
            text = String(localized: "Looking up…")
        }
        if site.ipv6ThroughTunnel > 0 {
            text += " · " + String(localized: "IPv6 through the VPN (no IPv6 on this network)")
        }
        return text
    }
}

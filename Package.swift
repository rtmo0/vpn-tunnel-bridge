// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Bridge",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "BridgeApp", targets: ["BridgeApp"]),
        .executable(name: "bridge", targets: ["bridge"]),
        .executable(name: "bridge-helper", targets: ["bridge-helper"]),
        .library(name: "BridgeCore", targets: ["BridgeCore"]),
    ],
    targets: [
        // Config parsing, UAPI and helper protocol. Shared by everything.
        .target(name: "BridgeCore"),
        // Client side: tunnel library, Keychain, connecting with credentials.
        .target(
            name: "BridgeClient",
            dependencies: ["BridgeCore"],
            linkerSettings: [.linkedFramework("Security")]
        ),
        // Menu bar app.
        .executableTarget(
            name: "BridgeApp",
            dependencies: ["BridgeCore", "BridgeClient"]
        ),
        // Command-line client.
        .executableTarget(
            name: "bridge",
            dependencies: ["BridgeCore", "BridgeClient"]
        ),
        // Privileged daemon.
        .executableTarget(
            name: "bridge-helper",
            dependencies: ["BridgeCore"],
            linkerSettings: [.linkedFramework("SystemConfiguration")]
        ),
        .testTarget(
            name: "BridgeCoreTests",
            dependencies: ["BridgeCore"]
        ),
    ],
    swiftLanguageModes: [.v5]
)

// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Bridge",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "bridge", targets: ["bridge"]),
        .executable(name: "bridge-helper", targets: ["bridge-helper"]),
        .library(name: "BridgeCore", targets: ["BridgeCore"]),
    ],
    targets: [
        .target(name: "BridgeCore"),
        .executableTarget(
            name: "bridge",
            dependencies: ["BridgeCore"]
        ),
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

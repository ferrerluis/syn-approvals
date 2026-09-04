// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Syn",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "Syn", targets: ["Syn"]),
    ],
    targets: [
        .executableTarget(
            name: "Syn",
            path: "Sources/Syn",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "SynTests",
            dependencies: ["Syn"],
            path: "Tests/SynTests",
            resources: [.copy("Fixtures")]
        ),
    ]
)

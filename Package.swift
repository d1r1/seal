// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "seal",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SealCore", targets: ["SealCore"]),
        .executable(name: "seal", targets: ["seal"]),
    ],
    targets: [
        .target(name: "SealCore"),
        .executableTarget(name: "seal", dependencies: ["SealCore"]),
        .testTarget(name: "SealCoreTests", dependencies: ["SealCore", "seal"]),
    ]
)

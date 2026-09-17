import Foundation
import XCTest
@testable import SealCore

/// The `seal-frost` helper for tests: the crate's release build, built once when missing.
enum FrostHelperFixture {
    static let packageRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    static let executable: URL = {
        let crate = packageRoot.appendingPathComponent("frost")
        let binary = crate.appendingPathComponent("target/release/seal-frost")
        if !FileManager.default.fileExists(atPath: binary.path) {
            let cargo = Process()
            cargo.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            cargo.arguments = ["cargo", "build", "--release", "--quiet"]
            cargo.currentDirectoryURL = crate
            try! cargo.run()
            cargo.waitUntilExit()
            precondition(cargo.terminationStatus == 0, "cargo build --release failed in \(crate.path)")
        }
        return binary
    }()

    static var helper: FrostHelper { FrostHelper(executable: executable) }
}

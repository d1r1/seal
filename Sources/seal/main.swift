import Foundation
import SealCore

// Git does not kill its signing program when it is killed itself; end with the parent so no Review is left behind.
let parentWatch = ParentWatch.onExit(of: getppid()) {
    FileHandle.standardError.write(Data((Exit.abandoned.message! + "\n").utf8))
    exit(Exit.abandoned.status)
}

let outcome = Seal.run(
    arguments: Array(CommandLine.arguments.dropFirst()),
    environment: ProcessInfo.processInfo.environment,
    workingDirectory: URL(fileURLWithPath: FileManager.default.currentDirectoryPath),
    review: { request in Review(request).awaitDecision() }
)
parentWatch.cancel()
if let message = outcome.message {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}
exit(outcome.status)

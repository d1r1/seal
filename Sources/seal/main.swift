import Foundation
import SealCore

let outcome = Seal.run(
    arguments: Array(CommandLine.arguments.dropFirst()),
    environment: ProcessInfo.processInfo.environment
)
if let message = outcome.message {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}
exit(outcome.status)

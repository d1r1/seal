import Foundation
import SealCore

let helper = FrostHelper.nextTo(Bundle.main.executableURL!.resolvingSymlinksInPath())

// `seal setup` is the one command that is not git's: it creates the group key once (ADR 0002).
if CommandLine.arguments.dropFirst().first == "setup" {
    exit(SetupCommand.run(group: GroupKey(), helper: helper))
}

// Git does not kill its signing program when it is killed itself; end with the parent so no Review is left behind.
let parentWatch = ParentWatch.onExit(of: getppid()) {
    FileHandle.standardError.write(Data((Exit.abandoned.message! + "\n").utf8))
    exit(Exit.abandoned.status)
}

let group = GroupKey()
let outcome = Seal.run(
    arguments: Array(CommandLine.arguments.dropFirst()),
    environment: ProcessInfo.processInfo.environment,
    workingDirectory: URL(fileURLWithPath: FileManager.default.currentDirectoryPath),
    group: group, helper: helper,
    review: { request in CardWindow(request, group: group).awaitDecision() }
)
parentWatch.cancel()
if let message = outcome.message {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}
exit(outcome.status)

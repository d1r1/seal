import Foundation

/// Notices when a process exits, so a Review never outlives the git that asked for it. Git does not kill the
/// signing program when it is itself killed (a caller's timeout, for example), so Seal watches its parent
/// and ends on its own. Uses the kernel's process events; no polling.
public enum ParentWatch {
    /// Calls `handler` on the main queue once `pid` exits. Returns the source; keep it alive for as long as the
    /// watch should last. If `pid` is already gone the handler fires at once. The handler runs at most once.
    @discardableResult
    public static func onExit(of pid: pid_t, handler: @escaping () -> Void) -> DispatchSourceProcess {
        let source = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: .main)
        var fired = false
        let once = {
            guard !fired else { return }
            fired = true
            handler()
        }
        source.setEventHandler(handler: once)
        source.resume()
        // A process that exited between the caller reading its pid and the source arming never delivers an event.
        if kill(pid, 0) != 0 && errno == ESRCH {
            DispatchQueue.main.async(execute: once)
        }
        return source
    }
}

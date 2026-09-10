import Darwin
import Dispatch
import Foundation

/// Runs only the system SSH client in release builds. A separate process group
/// lets cancellation stop SSH and its configured proxy helpers without ever
/// signaling the app or the user's shell group.
struct SSHProbeProcess: Sendable {
    private let executable: String
    private let timeout: Duration

    init(timeout: Duration = .seconds(15)) {
        executable = "/usr/bin/ssh"
        self.timeout = timeout
    }

    init(scpTimeout: Duration) {
        executable = "/usr/bin/scp"
        timeout = scpTimeout
    }

    init(keyScanTimeout: Duration) {
        executable = "/usr/bin/ssh-keyscan"
        timeout = keyScanTimeout
    }

#if DEBUG
    init(testExecutable: String, timeout: Duration) {
        executable = testExecutable
        self.timeout = timeout
    }
#endif

    func run(arguments: [String], privateStandardInput: Data? = nil) async throws -> SSHProbeOutput {
        try Task.checkCancellation()
        guard privateStandardInput.map({ $0.count <= 4_096 }) != false else {
            throw SSHProbeFailure.invalidOutput
        }
        let child = try spawn(arguments: arguments, privateStandardInput: privateStandardInput)
        defer { child.closePipes() }
        do {
            let deadline = ContinuousClock.now.advanced(by: timeout)
            var captured = Data()
            var diagnostics = Data()
            while true {
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw SSHProbeFailure.timedOut }
                try child.drain(captured: &captured, diagnostics: &diagnostics)
                if try child.hasExited() {
                    try child.drain(captured: &captured, diagnostics: &diagnostics)
                    let status = child.finishAfterExit()
                    return SSHProbeOutput(status: status, stdout: captured, diagnostics: diagnostics)
                }
                try await Task.sleep(for: .milliseconds(20))
            }
        } catch {
            child.stopAndReap()
            throw error
        }
    }

    private func spawn(arguments: [String], privateStandardInput: Data?) throws -> SpawnedSSHProbe {
        var output = [Int32]([-1, -1])
        var errors = [Int32]([-1, -1])
        var input = [Int32]([-1, -1])
        guard Darwin.pipe(&output) == 0 else { throw SSHProbeFailure.unavailable }
        defer {
            for descriptor in output where descriptor >= 0 { _ = Darwin.close(descriptor) }
        }
        guard Darwin.pipe(&errors) == 0 else { throw SSHProbeFailure.unavailable }
        defer {
            for descriptor in errors where descriptor >= 0 { _ = Darwin.close(descriptor) }
        }
        try Self.makeNonblocking(output[0])
        try Self.makeNonblocking(errors[0])
        let inputDescriptor: Int32
        if privateStandardInput != nil {
            guard Darwin.pipe(&input) == 0 else { throw SSHProbeFailure.unavailable }
            inputDescriptor = input[0]
        } else {
            inputDescriptor = Darwin.open("/dev/null", O_RDONLY)
            guard inputDescriptor >= 0 else { throw SSHProbeFailure.unavailable }
        }
        defer {
            for descriptor in input where descriptor >= 0 { _ = Darwin.close(descriptor) }
            if privateStandardInput == nil { _ = Darwin.close(inputDescriptor) }
        }

        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else {
            throw SSHProbeFailure.unavailable
        }
        defer { posix_spawn_file_actions_destroy(&actions) }
        for (source, destination) in [
            (inputDescriptor, STDIN_FILENO),
            (output[1], STDOUT_FILENO),
            (errors[1], STDERR_FILENO),
        ] {
            guard posix_spawn_file_actions_adddup2(&actions, source, destination) == 0 else {
                throw SSHProbeFailure.unavailable
            }
        }
        for descriptor in Set([output[0], output[1], errors[0], errors[1], input[0], input[1], inputDescriptor])
        where descriptor > STDERR_FILENO {
            guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else {
                throw SSHProbeFailure.unavailable
            }
        }

        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else {
            throw SSHProbeFailure.unavailable
        }
        defer { posix_spawnattr_destroy(&attributes) }
        let spawnFlags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT
        guard posix_spawnattr_setflags(&attributes, Int16(spawnFlags)) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0 else {
            throw SSHProbeFailure.unavailable
        }

        let duplicatedArguments = ([executable] + arguments).map { strdup($0) }
        guard duplicatedArguments.allSatisfy({ $0 != nil }) else {
            for argument in duplicatedArguments { free(argument) }
            throw SSHProbeFailure.unavailable
        }
        defer { for argument in duplicatedArguments { free(argument) } }
        var argv = duplicatedArguments + [nil]
        var childEnvironment = ProcessInfo.processInfo.environment
        childEnvironment["LC_ALL"] = "C"
        childEnvironment["LANG"] = "C"
        let duplicatedEnvironment = childEnvironment
            .map { strdup("\($0.key)=\($0.value)") }
        guard duplicatedEnvironment.allSatisfy({ $0 != nil }) else {
            for value in duplicatedEnvironment { free(value) }
            throw SSHProbeFailure.unavailable
        }
        defer { for value in duplicatedEnvironment { free(value) } }
        var environment = duplicatedEnvironment + [nil]
        var processID: pid_t = 0
        let result = executable.withCString { path in
            argv.withUnsafeMutableBufferPointer { buffer in
                environment.withUnsafeMutableBufferPointer { environmentBuffer in
                    posix_spawn(
                        &processID,
                        path,
                        &actions,
                        &attributes,
                        buffer.baseAddress!,
                        environmentBuffer.baseAddress!
                    )
                }
            }
        }
        guard result == 0, processID > 1 else { throw SSHProbeFailure.unavailable }

        if let privateStandardInput {
            _ = Darwin.close(input[0]); input[0] = -1
            do {
                try privateStandardInput.withUnsafeBytes { bytes in
                    var offset = 0
                    while offset < bytes.count {
                        let count = Darwin.write(
                            input[1], bytes.baseAddress!.advanced(by: offset), bytes.count - offset
                        )
                        if count < 0 {
                            if errno == EINTR { continue }
                            throw SSHProbeFailure.unavailable
                        }
                        offset += count
                    }
                }
            } catch {
                _ = Darwin.close(input[1]); input[1] = -1
                _ = kill(-processID, SIGKILL)
                var status: Int32 = 0
                while waitpid(processID, &status, 0) == -1 && errno == EINTR {}
                throw error
            }
            _ = Darwin.close(input[1]); input[1] = -1
        }

        _ = Darwin.close(output[1]); output[1] = -1
        _ = Darwin.close(errors[1]); errors[1] = -1
        let child = SpawnedSSHProbe(
            processID: processID,
            outputDescriptor: output[0],
            errorDescriptor: errors[0]
        )
        output[0] = -1
        errors[0] = -1
        return child
    }

    private static func makeNonblocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != -1 else {
            throw SSHProbeFailure.unavailable
        }
    }
}

private final class SpawnedSSHProbe: @unchecked Sendable {
    private let processID: pid_t
    private var outputDescriptor: Int32
    private var errorDescriptor: Int32
    private var reaped = false
    private var reaperScheduled = false

    init(processID: pid_t, outputDescriptor: Int32, errorDescriptor: Int32) {
        self.processID = processID
        self.outputDescriptor = outputDescriptor
        self.errorDescriptor = errorDescriptor
    }

    deinit {
        if !reaped && !reaperScheduled {
            signalOwnedGroup(SIGKILL)
            scheduleDetachedReaper()
        }
        closePipes()
    }

    func drain(captured: inout Data, diagnostics: inout Data) throws {
        try Self.drain(outputDescriptor, captured: &captured, limit: 65_536)
        try Self.drain(errorDescriptor, captured: &diagnostics, limit: 16_384)
    }

    func hasExited() throws -> Bool {
        guard !reaped else { return true }
        var information = siginfo_t()
        let result = waitid(
            P_PID,
            id_t(processID),
            &information,
            WEXITED | WNOHANG | WNOWAIT
        )
        if result == 0 { return information.si_pid == processID }
        if errno == EINTR { return false }
        if errno == ECHILD {
            // Another reaper means this object no longer owns a reserved PID.
            // Never signal that number again because it may already be reused.
            reaped = true
        }
        throw SSHProbeFailure.unavailable
    }

    func stopAndReap() {
        guard !reaped, !reaperScheduled else { return }
        signalOwnedGroup(SIGTERM)
        // This bounded synchronous grace period also works while the Swift task
        // is canceled; cancellation-aware sleeps would return immediately.
        for _ in 0..<25 {
            if (try? hasExited()) == true { break }
            _ = Darwin.poll(nil, 0, 10)
        }
        signalOwnedGroup(SIGKILL)
        if reapWithinBound() == nil { scheduleDetachedReaper() }
    }

    func finishAfterExit() -> Int32 {
        // The unreaped leader keeps its PID reserved while the owned group is
        // terminated, preventing a later group signal from hitting a reused ID.
        signalOwnedGroup(SIGTERM)
        for _ in 0..<5 {
            _ = Darwin.poll(nil, 0, 10)
        }
        signalOwnedGroup(SIGKILL)
        if let status = reapWithinBound() { return status }
        scheduleDetachedReaper()
        return 255
    }

    func closePipes() {
        if outputDescriptor >= 0 {
            _ = Darwin.close(outputDescriptor)
            outputDescriptor = -1
        }
        if errorDescriptor >= 0 {
            _ = Darwin.close(errorDescriptor)
            errorDescriptor = -1
        }
    }

    private func signalOwnedGroup(_ signal: Int32) {
        // POSIX_SPAWN_SETPGROUP with pgroup 0 makes this exact child PID the
        // group ID. Never fall back to the caller's shared process group.
        guard processID > 1, !reaped, !reaperScheduled else { return }
        _ = kill(-processID, signal)
    }

    private func reapWithinBound() -> Int32? {
        guard !reaped else { return nil }
        for _ in 0..<25 {
            var status: Int32 = 0
            let result = waitpid(processID, &status, WNOHANG)
            if result == processID {
                reaped = true
                return Self.exitStatus(status)
            }
            if result == -1 && errno == ECHILD {
                reaped = true
                return 255
            }
            if result == -1 && errno != EINTR { return nil }
            _ = Darwin.poll(nil, 0, 10)
        }
        return nil
    }

    private func scheduleDetachedReaper() {
        guard !reaped, !reaperScheduled else { return }
        reaperScheduled = true
        let childPID = processID
        DispatchQueue.global(qos: .utility).async {
            var status: Int32 = 0
            while waitpid(childPID, &status, 0) == -1 && errno == EINTR {}
        }
    }

    private static func exitStatus(_ status: Int32) -> Int32 {
        let signal = status & 0x7f
        return signal == 0 ? (status >> 8) & 0xff : 128 + signal
    }

    private static func drain(
        _ descriptor: Int32,
        captured: inout Data,
        limit: Int
    ) throws {
        var buffer = [UInt8](repeating: 0, count: 4096)
        for _ in 0..<17 {
            let count = read(descriptor, &buffer, buffer.count)
            if count == 0 { return }
            if count < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK { return }
                if errno == EINTR { continue }
                throw SSHProbeFailure.unavailable
            }
            guard captured.count + count <= limit else { throw SSHProbeFailure.tooMuchOutput }
            captured.append(contentsOf: buffer.prefix(count))
        }
    }
}

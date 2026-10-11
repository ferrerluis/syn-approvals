import CryptoKit
import Darwin
import Foundation

enum RequestHistoryStatus: String, Codable, Sendable {
    case pending, approvalSent, denialSent, approved, denied, timedOut, canceled, failed, unconfirmed

    var label: String {
        switch self {
        case .pending: "Pending"
        case .approvalSent: "Approval sent — awaiting receipt"
        case .denialSent: "Denial sent — awaiting receipt"
        case .approved: "Approved"
        case .denied: "Denied"
        case .timedOut: "Timed out"
        case .canceled: "Canceled"
        case .failed: "Failed"
        case .unconfirmed: "Unconfirmed"
        }
    }
}

struct RequestHistoryEntry: Codable, Identifiable, Equatable, Sendable {
    let targetID: String
    let requestID: String
    let requestHash: Data
    let releaseID: String
    let releaseCommit: String
    let requestedAt: Date
    let expiresAt: Date
    let invokingUID: UInt32
    let runAsUID: UInt32
    var completedAt: Date?
    var status: RequestHistoryStatus
    var confirmed: Bool
    var targetSignatureVerified: Bool? = nil
    var id: String { "\(targetID):\(requestID)" }

    init(_ request: VerifiedApprovalRequest) {
        targetID = request.targetID
        requestID = request.requestID.hex
        requestHash = request.payloadHash
        releaseID = request.releaseID
        releaseCommit = request.releaseCommit
        requestedAt = request.issuedAt
        expiresAt = request.expiresAt
        invokingUID = request.invokingUID
        runAsUID = request.runAsUID
        status = .pending
        confirmed = false
    }
}

struct RequestResultReceipt: Sendable {
    let targetID: String
    let requestID: String
    let requestHash: Data
    let releaseID: String
    let releaseCommit: String
    let requestedAt: Date
    let completedAt: Date
    let status: RequestHistoryStatus
    let invokingUID: UInt32
    let runAsUID: UInt32

    init(_ data: Data, target: TargetRecord) throws {
        guard let key = target.publicKey else { throw SynProtocolError.invalid("invalid receipt target key") }
        let (payload, _) = try SynProtocol.verifyCOSE(data, key: key)
        let targetID = target.targetID
        let map = try CBORCodec.decodeCanonical(payload).integerKeyedMap()
        let release = ReleaseIdentity.current
        let commit = release.commit == "development" ? SynProtocol.developmentCommit : release.commit
        guard map.count == 11, map[10]?.textValue == "org.syn-approvals.permission-result.v1",
              map[0]?.textValue == targetID,
              let id = map[1]?.bytesValue, id.count == 16,
              let hash = map[2]?.bytesValue, hash.count == 32,
              map[3]?.textValue == release.releaseID, map[4]?.textValue == commit,
              let requested = Self.integer(map[5]), let completed = Self.integer(map[6]),
              requested >= 0, completed >= requested,
              let outcome = map[7]?.unsignedValue,
              let invoking = map[8]?.unsignedValue, let invokingUID = UInt32(exactly: invoking),
              let runAs = map[9]?.unsignedValue, let runAsUID = UInt32(exactly: runAs) else {
            throw SynProtocolError.invalid("invalid permission receipt")
        }
        let statuses: [UInt64: RequestHistoryStatus] = [
            1: .approved, 2: .denied, 3: .timedOut, 4: .canceled, 5: .failed, 6: .unconfirmed,
        ]
        guard let status = statuses[outcome] else { throw SynProtocolError.invalid("unknown permission result") }
        self.targetID = targetID
        requestID = id.hex
        requestHash = hash
        releaseID = release.releaseID
        releaseCommit = commit
        requestedAt = Date(timeIntervalSince1970: Double(requested) / 1_000)
        completedAt = Date(timeIntervalSince1970: Double(completed) / 1_000)
        self.status = status
        self.invokingUID = invokingUID
        self.runAsUID = runAsUID
    }

    private static func integer(_ value: CBOR?) -> Int64? {
        if let unsigned = value?.unsignedValue { return Int64(exactly: unsigned) }
        return value?.negativeValue
    }

    func matches(_ entry: RequestHistoryEntry) -> Bool {
        entry.targetID == targetID && entry.requestID == requestID && entry.requestHash == requestHash
            && entry.releaseID == releaseID && entry.releaseCommit == releaseCommit
            && abs(entry.requestedAt.timeIntervalSince(requestedAt)) < 0.001
            && entry.invokingUID == invokingUID && entry.runAsUID == runAsUID
    }
}

struct RequestHistoryStore: Sendable {
    let fileURL: URL

    init(fileURL: URL? = nil) throws {
        if let fileURL { self.fileURL = fileURL; return }
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                              appropriateFor: nil, create: true)
        let directory = base.appendingPathComponent("Syn", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        self.fileURL = directory.appendingPathComponent("request-history.json")
    }

    func load() throws -> [RequestHistoryEntry] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [] }
        let data = try Data(contentsOf: fileURL)
        guard data.count <= 32 * 1_024 * 1_024 else { throw SynProtocolError.invalid("history is too large") }
        return try JSONDecoder().decode([RequestHistoryEntry].self, from: data)
    }

    func save(_ entries: [RequestHistoryEntry]) throws {
        let data = try JSONEncoder().encode(Self.retained(entries))
        let temporary = fileURL.appendingPathExtension(UUID().uuidString + ".tmp")
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close(); try? FileManager.default.removeItem(at: temporary) }
        try handle.write(contentsOf: data)
        try handle.synchronize()
        guard rename(temporary.path, fileURL.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    static func retained(_ entries: [RequestHistoryEntry]) -> [RequestHistoryEntry] {
        var counts: [String: Int] = [:]
        return entries.sorted { $0.requestedAt > $1.requestedAt }.filter { entry in
            guard entry.completedAt != nil else { return true }
            counts[entry.targetID, default: 0] += 1
            return counts[entry.targetID, default: 0] <= 1_000
        }
    }
}

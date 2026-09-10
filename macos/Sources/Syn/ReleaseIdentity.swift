import Foundation

/// The trusted app bundle supplies this identity; remote messages cannot set it.
struct ReleaseIdentity: Decodable, Equatable, Sendable {
    let schemaVersion: Int
    let releaseID: String
    let commit: String

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case releaseID = "release_id"
        case commit
    }

    static let developmentID = "00000000000000"

    static let current: ReleaseIdentity = {
        guard let url = Bundle.main.url(forResource: "release", withExtension: "json") else {
            // SwiftPM tests and unbundled local builds only. A packaged app
            // missing its metadata fails closed, not as a development release.
            return ReleaseIdentity(schemaVersion: 1,
                                   releaseID: Bundle.main.bundleURL.pathExtension == "app" ? "invalid" : developmentID,
                                   commit: "development")
        }
        return (try? load(Data(contentsOf: url)))
            ?? ReleaseIdentity(schemaVersion: 0, releaseID: "invalid", commit: "invalid")
    }()

    static func load(_ data: Data) throws -> ReleaseIdentity {
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.schemaVersion == 1, validID(value.releaseID),
              value.commit.utf8.count == 40,
              value.commit.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw SynProtocolError.invalid("Invalid app release metadata")
        }
        return value
    }

    static func validID(_ value: String) -> Bool {
        guard value.utf8.count == 14,
              value.utf8.allSatisfy({ (48...57).contains($0) }) else { return false }
        if value == developmentID { return true }
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMddHHmmss"
        formatter.isLenient = false
        guard value.prefix(4) >= "2026", let date = formatter.date(from: value) else { return false }
        return formatter.string(from: date) == value
    }
}

import Foundation

enum SafeDisplay {
    private static let secretWords = [
        "apikey", "api_key", "authorization", "bearer", "credential", "password",
        "private-key", "private_key", "secret", "token",
    ]

    static func render(_ data: Data) -> String {
        guard let text = String(data: data, encoding: .utf8), Data(text.utf8) == data else {
            return "hex:" + data.hex
        }
        // Quoting distinguishes text from the raw-byte fallback, including
        // literal "hex:ff" and the empty string. Escape every non-ASCII scalar
        // so invisible characters, homoglyphs and Unicode normalization cannot
        // disguise the bytes a person is approving. This is display-only;
        // these strings must never be reconstructed into a shell command.
        var output = "\""
        for scalar in text.unicodeScalars {
            if scalar == "\\" || scalar == "\"" {
                output += "\\"
                output.unicodeScalars.append(scalar)
            } else if !(0x20...0x7e).contains(scalar.value) {
                output += "\\u{\(String(scalar.value, radix: 16, uppercase: true))}"
            } else {
                output.unicodeScalars.append(scalar)
            }
        }
        return output + "\""
    }

    static func likelyContainsSecret(_ data: Data) -> Bool {
        guard let text = String(data: data, encoding: .utf8)?.lowercased() else { return false }
        return secretWords.contains { text.contains($0) }
    }

}

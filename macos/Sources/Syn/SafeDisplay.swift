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
        var output = ""
        for scalar in text.unicodeScalars {
            if scalar.value < 0x20 || scalar.value == 0x7f || isUnsafe(scalar) {
                output += "\\u{\(String(scalar.value, radix: 16, uppercase: true))}"
            } else {
                output.unicodeScalars.append(scalar)
            }
        }
        return output.isEmpty ? "(empty)" : output
    }

    static func likelyContainsSecret(_ data: Data) -> Bool {
        guard let text = String(data: data, encoding: .utf8)?.lowercased() else { return false }
        return secretWords.contains { text.contains($0) }
    }

    private static func isUnsafe(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x200b...0x200f, 0x202a...0x202e, 0x2060...0x2069, 0xfeff:
            true
        default:
            scalar.properties.isWhitespace && scalar != " " && scalar != "\t"
        }
    }
}

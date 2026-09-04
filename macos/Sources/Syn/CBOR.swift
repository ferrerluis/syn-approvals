import Foundation

indirect enum CBOR: Equatable, Sendable {
    case unsigned(UInt64)
    case negative(Int64)
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([(CBOR, CBOR)])
    case tag(UInt64, CBOR)
    case bool(Bool)
    case null

    static func == (lhs: CBOR, rhs: CBOR) -> Bool {
        switch (lhs, rhs) {
        case let (.unsigned(a), .unsigned(b)): a == b
        case let (.negative(a), .negative(b)): a == b
        case let (.bytes(a), .bytes(b)): a == b
        case let (.text(a), .text(b)): a == b
        case let (.array(a), .array(b)): a == b
        case let (.map(a), .map(b)):
            a.count == b.count && zip(a, b).allSatisfy { pair in
                pair.0.0 == pair.1.0 && pair.0.1 == pair.1.1
            }
        case let (.tag(a, av), .tag(b, bv)): a == b && av == bv
        case let (.bool(a), .bool(b)): a == b
        case (.null, .null): true
        default: false
        }
    }
}

enum CBORError: Error, LocalizedError {
    case truncated
    case unsupported(String)
    case invalid(String)
    case nonCanonical

    var errorDescription: String? {
        switch self {
        case .truncated: "CBOR input is truncated"
        case let .unsupported(message), let .invalid(message): message
        case .nonCanonical: "CBOR input is not deterministic"
        }
    }
}

struct CBORCodec: Sendable {
    static let maximumDepth = 32
    static let maximumCollectionItems = 4096

    static func decodeCanonical(_ data: Data) throws -> CBOR {
        var decoder = Decoder(data: data)
        let value = try decoder.decode(depth: 0)
        guard decoder.position == data.count else { throw CBORError.invalid("trailing CBOR data") }
        guard try encode(value) == data else { throw CBORError.nonCanonical }
        return value
    }

    static func encode(_ value: CBOR) throws -> Data {
        var output = Data()
        try encode(value, into: &output, depth: 0)
        return output
    }

    private static func encode(_ value: CBOR, into output: inout Data, depth: Int) throws {
        guard depth <= maximumDepth else { throw CBORError.invalid("CBOR nesting is too deep") }
        switch value {
        case let .unsigned(number): appendMajor(0, number, to: &output)
        case let .negative(number):
            guard number < 0 else { throw CBORError.invalid("negative CBOR value is non-negative") }
            appendMajor(1, UInt64(bitPattern: -1 - number), to: &output)
        case let .bytes(bytes):
            appendMajor(2, UInt64(bytes.count), to: &output)
            output.append(bytes)
        case let .text(text):
            guard let bytes = text.data(using: .utf8) else { throw CBORError.invalid("invalid text") }
            appendMajor(3, UInt64(bytes.count), to: &output)
            output.append(bytes)
        case let .array(values):
            guard values.count <= maximumCollectionItems else { throw CBORError.invalid("array is too large") }
            appendMajor(4, UInt64(values.count), to: &output)
            for item in values { try encode(item, into: &output, depth: depth + 1) }
        case let .map(entries):
            guard entries.count <= maximumCollectionItems else { throw CBORError.invalid("map is too large") }
            var encoded: [(Data, CBOR)] = []
            for (key, value) in entries { encoded.append((try encode(key), value)) }
            encoded.sort { left, right in
                left.0.count == right.0.count ? left.0.lexicographicallyPrecedes(right.0) : left.0.count < right.0.count
            }
            for pair in zip(encoded, encoded.dropFirst()) where pair.0.0 == pair.1.0 {
                throw CBORError.invalid("duplicate map key")
            }
            appendMajor(5, UInt64(encoded.count), to: &output)
            for (key, value) in encoded {
                output.append(key)
                try encode(value, into: &output, depth: depth + 1)
            }
        case let .tag(tag, inner):
            appendMajor(6, tag, to: &output)
            try encode(inner, into: &output, depth: depth + 1)
        case let .bool(value): output.append(value ? 0xf5 : 0xf4)
        case .null: output.append(0xf6)
        }
    }

    private static func appendMajor(_ major: UInt8, _ value: UInt64, to output: inout Data) {
        let prefix = major << 5
        switch value {
        case 0...23: output.append(prefix | UInt8(value))
        case 24...0xff:
            output.append(prefix | 24); output.append(UInt8(value))
        case 0x100...0xffff:
            output.append(prefix | 25); appendInteger(UInt16(value), to: &output)
        case 0x1_0000...0xffff_ffff:
            output.append(prefix | 26); appendInteger(UInt32(value), to: &output)
        default:
            output.append(prefix | 27); appendInteger(value, to: &output)
        }
    }

    private static func appendInteger<T: FixedWidthInteger>(_ value: T, to output: inout Data) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { output.append(contentsOf: $0) }
    }

    private struct Decoder {
        let data: Data
        var position = 0

        mutating func decode(depth: Int) throws -> CBOR {
            guard depth <= CBORCodec.maximumDepth else { throw CBORError.invalid("CBOR nesting is too deep") }
            let initial = try byte()
            let major = initial >> 5
            let additional = initial & 0x1f
            switch major {
            case 0: return .unsigned(try argument(additional))
            case 1:
                let value = try argument(additional)
                guard value <= UInt64(Int64.max) else { throw CBORError.unsupported("negative integer is too small") }
                return .negative(-1 - Int64(value))
            case 2:
                let count = try count(additional)
                return .bytes(try bytes(count))
            case 3:
                let count = try count(additional)
                let value = try bytes(count)
                guard let text = String(data: value, encoding: .utf8) else { throw CBORError.invalid("invalid UTF-8 text") }
                return .text(text)
            case 4:
                let count = try count(additional)
                return .array(try (0..<count).map { _ in try decode(depth: depth + 1) })
            case 5:
                let count = try count(additional)
                var entries: [(CBOR, CBOR)] = []
                for _ in 0..<count { entries.append((try decode(depth: depth + 1), try decode(depth: depth + 1))) }
                return .map(entries)
            case 6: return .tag(try argument(additional), try decode(depth: depth + 1))
            case 7 where additional == 20: return .bool(false)
            case 7 where additional == 21: return .bool(true)
            case 7 where additional == 22: return .null
            default: throw CBORError.unsupported("indefinite, floating-point, and simple CBOR values are unsupported")
            }
        }

        mutating func byte() throws -> UInt8 {
            guard position < data.count else { throw CBORError.truncated }
            defer { position += 1 }
            return data[position]
        }

        mutating func bytes(_ count: Int) throws -> Data {
            guard count >= 0, position <= data.count - count else { throw CBORError.truncated }
            defer { position += count }
            return data.subdata(in: position..<(position + count))
        }

        mutating func count(_ additional: UInt8) throws -> Int {
            let value = try argument(additional)
            guard value <= UInt64(CBORCodec.maximumCollectionItems) else { throw CBORError.invalid("CBOR collection is too large") }
            return Int(value)
        }

        mutating func argument(_ additional: UInt8) throws -> UInt64 {
            switch additional {
            case 0...23: return UInt64(additional)
            case 24: return UInt64(try byte())
            case 25: return try integer(UInt16.self)
            case 26: return try integer(UInt32.self)
            case 27: return try integer(UInt64.self)
            default: throw CBORError.unsupported("indefinite-length CBOR is unsupported")
            }
        }

        mutating func integer<T: FixedWidthInteger>(_ type: T.Type) throws -> UInt64 {
            let raw = try bytes(MemoryLayout<T>.size)
            return raw.withUnsafeBytes { pointer in
                let value = pointer.loadUnaligned(as: T.self)
                return UInt64(value.bigEndian)
            }
        }
    }
}

extension CBOR {
    func integerKeyedMap() throws -> [UInt64: CBOR] {
        guard case let .map(entries) = self else { throw CBORError.invalid("expected CBOR map") }
        var output: [UInt64: CBOR] = [:]
        for (key, value) in entries {
            guard case let .unsigned(number) = key, output.updateValue(value, forKey: number) == nil else {
                throw CBORError.invalid("map keys must be unique unsigned integers")
            }
        }
        return output
    }

    var unsignedValue: UInt64? { if case let .unsigned(value) = self { value } else { nil } }
    var negativeValue: Int64? { if case let .negative(value) = self { value } else { nil } }
    var bytesValue: Data? { if case let .bytes(value) = self { value } else { nil } }
    var textValue: String? { if case let .text(value) = self { value } else { nil } }
    var arrayValue: [CBOR]? { if case let .array(value) = self { value } else { nil } }
    var boolValue: Bool? { if case let .bool(value) = self { value } else { nil } }
    var isNull: Bool { if case .null = self { true } else { false } }
}

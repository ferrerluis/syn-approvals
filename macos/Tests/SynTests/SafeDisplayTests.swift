import Foundation
import Testing
@testable import Syn

@Test func displaySeparatesBytesFromLiteralEscapeSyntax() {
    let pairs: [(Data, Data)] = [
        (Data(), Data("(empty)".utf8)),
        (Data([0xff]), Data("hex:ff".utf8)),
        (Data([0x0a]), Data(#"\u{A}"#.utf8)),
        (Data("\u{202e}".utf8), Data(#"\u{202E}"#.utf8)),
        (Data("é".utf8), Data("e\u{301}".utf8)),
        (Data("a".utf8), Data("а".utf8)), // Latin versus Cyrillic.
        (Data("a b".utf8), Data("a\u{a0}b".utf8)),
    ]
    for (left, right) in pairs {
        #expect(left != right)
        #expect(SafeDisplay.render(left) != SafeDisplay.render(right))
    }
    #expect(SafeDisplay.render(Data()) == "\"\"")
    #expect(SafeDisplay.render(Data("\"\\".utf8)) == #""\"\\""#)
}

@Test func displayEscapesAllNonASCIIAndControlScalars() {
    for value: UInt32 in [0, 9, 10, 0x7f, 0x85, 0xad, 0x61c, 0x200d, 0x202e, 0x2066, 0xfe0f, 0xfeff] {
        let scalar = Unicode.Scalar(value)!
        let text = "a" + String(scalar) + "b"
        let rendered = SafeDisplay.render(Data(text.utf8))
        #expect(rendered == "\"a\\u{\(String(value, radix: 16, uppercase: true))}b\"")
        #expect(rendered.utf8.allSatisfy { (0x20...0x7e).contains($0) })
    }
}

@Test func everySingleAndTwoByteInputHasADistinctDisplay() {
    // Includes invalid UTF-8 and literal delimiters. No real invocation data.
    var rendered = Set<String>()
    #expect(rendered.insert(SafeDisplay.render(Data())).inserted)
    for first in UInt8.min...UInt8.max {
        #expect(rendered.insert(SafeDisplay.render(Data([first]))).inserted)
        for second in UInt8.min...UInt8.max {
            #expect(rendered.insert(SafeDisplay.render(Data([first, second]))).inserted)
        }
    }
    #expect(rendered.count == 65_793)
}

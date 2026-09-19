//
//  DER.swift
//
//  fravash: the smallest DER reader that can find one element inside a
//  39794-5 DG2, written to be safe on input we did not produce.
//

import Foundation

/**
 A tag-directed walk over DER encoded bytes.

 WHY THIS IS NOT A GENERAL ASN.1 PARSER, AND MUST NOT BECOME ONE. It exists to
 reach `representationData2D` inside an ISO/IEC 39794-5 facial record and stop.
 That schema carries landmarks, quality blocks, capture device details and
 anthropometric metadata, none of which anything downstream reads. Every field
 parsed is another place to be wrong about bytes an attacker can influence, so
 the smallest reader that answers the question is the right one.

 EVERYTHING HERE IS BOUNDS CHECKED AND RETURNS `nil` RATHER THAN THROWING OR
 TRAPPING. The input arrives from an NFC device we do not control and have not
 authenticated at this point in the read, so a malformed length must produce
 "not found" and never an out of range index. Swift array indexing traps, and a
 trap is a crash on a real person's phone.

 No em dashes, by design.
 */
public enum DER {

    /// Where a matched element's content begins and ends.
    public struct Element {
        public let contentStart: Int
        public let contentEnd: Int
    }

    /**
     Find the first direct child with `tag` in `data[from..<to]`.

     SIBLINGS ARE SEARCHED, NOT COUNTED. Most members at the levels this walks
     are OPTIONAL, so an element's position is not stable: the two official ICAO
     reference vectors differ in exactly that way, one carrying only mandatory
     fields and the other carrying all of them. Searching by tag reads both.

     Only DIRECT children are considered. Descending automatically would let a
     tag deep inside an unrelated branch satisfy a lookup that should have
     failed, which is how a parser starts returning confident nonsense.
     */
    public static func find(tag: Int, in data: [UInt8], from: Int, to: Int) -> Element? {
        var i = from
        /* `to <= data.count` is asserted once here rather than trusted from the
           caller, because every bound below is derived from it. */
        let end = min(to, data.count)

        while i < end {
            guard let header = readHeader(data, at: i, limit: end) else { return nil }
            let contentEnd = header.contentStart + header.length
            /* A length that runs past the parent's end is malformed. Stop rather
               than clamping: a clamped read would hand back a truncated element
               that looks valid to the caller. */
            guard contentEnd <= end, contentEnd >= header.contentStart else { return nil }

            if header.tag == tag {
                return Element(contentStart: header.contentStart, contentEnd: contentEnd)
            }
            /* A zero length element is legal and must still advance, or this
               loops forever on it. */
            i = contentEnd
            if i <= header.tagStart { return nil }
        }
        return nil
    }

    // MARK: - fravash: reading a SEQUENCE the issuer wrote

    /* THE FOUR UNIVERSAL TAGS THIS FILE'S CALLERS CHECK, named once.
       A caller writing `0x30` inline is a caller who can write `0x03` by
       accident and get a shape check that silently never matches. */
    public static let integer = 0x02
    public static let octetString = 0x04
    public static let objectIdentifier = 0x06
    public static let sequence = 0x30


    /**
     One direct child, with its tag.

     `Element` deliberately carries no tag, because `find(tag:)` already knows
     what it matched. Enumeration does not: the caller is checking the SHAPE of
     what it found, and a shape check that cannot see tags is not one.
     */
    public struct Child {
        public let tag: Int
        public let contentStart: Int
        public let contentEnd: Int
    }

    /// The largest number of direct children this will return before refusing.
    /**
     A SEQUENCE OF with more members than this is not a data group hash table.
     ICAO's own bound is 16 rows, this is far above it, and it exists only so a
     malformed length cannot make us build an unbounded array out of one short
     buffer. Refusing rather than truncating: a truncated table is a table with
     rows missing and it looks exactly like a valid smaller one.
     */
    private static let childLimit = 1024

    /**
     Every direct child of `data[from..<to]`, in document order.

     WHY THIS IS NOT `find(tag:)` IN A LOOP. The SOD's hash table is a SEQUENCE
     OF identically tagged members, so searching by tag finds the first and hides
     the rest. Position and count are the whole content of this structure, which
     is the opposite of the 39794-5 case the file header describes, where
     members are optional and position is unstable.

     NIL ON ANY MALFORMED ELEMENT, rather than the children found so far. A
     partial list is a hash table with rows silently missing, and since the
     account number commits to the whole table, a row dropped here is a wrong
     number that is stable across reads and therefore invisible. Every other
     refusal in this file exists to avoid confident nonsense; this one exists to
     avoid a confident WRONG TABLE.
     */
    public static func children(in data: [UInt8], from: Int, to: Int) -> [Child]? {
        var out: [Child] = []
        var i = from
        let end = min(to, data.count)
        /* The caller's `to` running past the buffer is malformed input, not
           something to quietly clamp: it means the parent length lied. */
        guard to <= data.count else { return nil }

        while i < end {
            guard let header = readHeader(data, at: i, limit: end) else { return nil }
            let contentEnd = header.contentStart + header.length
            guard contentEnd <= end, contentEnd >= header.contentStart else { return nil }
            guard out.count < childLimit else { return nil }
            out.append(Child(tag: header.tag,
                             contentStart: header.contentStart,
                             contentEnd: contentEnd))
            /* A zero length element is legal and must still advance. */
            i = contentEnd
            if i <= header.tagStart { return nil }
        }
        return out
    }

    /**
     A DER INTEGER's content as an `Int`, two's complement, big endian.

     REFUSES MORE THAN EIGHT CONTENT BYTES rather than wrapping or saturating.
     This is the Swift half of the defect that produced data group 0 on the
     TypeScript side: a reader that quietly turns a number it cannot hold into
     some other number puts a row the document never declared into a commitment.
     Nine bytes of leading zeros is refused too, deliberately, because accepting
     it means deciding how much redundant padding is "really" in range, and the
     honest bound is the one the return type can hold.

     LEADING ZEROS ARE NOT STRIPPED FIRST, AND THAT IS THE POINT. A four byte
     encoding of seventeen is seventeen here, which is what the document says.
     The fork's previous reader lost that row entirely.
     */
    public static func integerValue(_ data: [UInt8], from: Int, to: Int) -> Int? {
        guard from >= 0, to <= data.count, from < to else { return nil }
        let length = to - from
        guard length <= 8 else { return nil }

        let negative = (data[from] & 0x80) != 0
        var value = negative ? -1 : 0
        for i in from..<to {
            value = (value << 8) | Int(data[i])
        }
        return value
    }

    private struct Header {
        let tag: Int
        let tagStart: Int
        let contentStart: Int
        let length: Int
    }

    /// Read one tag and length. `nil` on anything malformed or out of bounds.
    private static func readHeader(_ data: [UInt8], at start: Int, limit: Int) -> Header? {
        var i = start
        guard i < limit else { return nil }

        var tag = Int(data[i])
        i += 1
        /* A low five bits of all ones means the tag number continues into
           following bytes. Only two byte tags occur in this structure (0x5F2E
           and 0x7F2E), and more than two is refused rather than supported: an
           unbounded tag loop is a denial of service on malformed input. */
        if (tag & 0x1F) == 0x1F {
            guard i < limit else { return nil }
            tag = (tag << 8) | Int(data[i])
            i += 1
            /* If the continuation bit is still set, the tag is longer than
               anything this structure uses. Refuse it. */
            if (data[i - 1] & 0x80) != 0 { return nil }
        }

        guard i < limit else { return nil }
        var length = Int(data[i])
        i += 1

        if (length & 0x80) != 0 {
            let count = length & 0x7F
            /* Indefinite length (0x80) is not valid DER, and a length field
               wider than four bytes describes something larger than any data
               group can be. Both are refused. */
            guard count >= 1, count <= 4, i + count <= limit else { return nil }
            length = 0
            for _ in 0..<count {
                length = (length << 8) | Int(data[i])
                i += 1
            }
        }
        guard length >= 0 else { return nil }

        return Header(tag: tag, tagStart: start, contentStart: i, length: length)
    }
}

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

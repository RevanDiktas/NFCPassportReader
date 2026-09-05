//
//  CardCapabilities.swift
//
//  fravash, 2026-09-05.
//

import Foundation

/**
 fravash: WHAT THIS CHIP SAYS IT CAN DO, ASKED RATHER THAN ASSUMED.

 WHY THIS FILE EXISTS. Reading a data group costs one round trip per chunk, and
 on a slow chip a round trip is about 127 milliseconds no matter how many bytes
 it carries. Measured on a real Dutch passport issued in January 2017: DG2 is
 14884 bytes, the library reads it 160 bytes at a time, and those 93 round trips
 alone take 12.3 seconds out of the roughly 20 that CoreNFC allows a connected
 tag. The document could not be enrolled at all. Raising the read to 255 bytes
 fixed it with about 5 seconds to spare, which is a margin and not a solution:
 the next chip we meet may be slower still.

 EXTENDED LENGTH IS THE REAL ANSWER. A chip that accepts extended Lc and Le
 fields can be asked for thousands of bytes in one command, which turns those 93
 round trips into a handful. But ISO/IEC 7816-4 makes extended length OPTIONAL
 for the card while mandatory for the terminal, so a terminal MUST establish that
 the card supports it before using it. Sending an extended APDU to a chip that
 does not understand one does not politely degrade: it is a protocol error
 partway through a read we cannot afford to restart.

 SO THIS ASKS. ISO/IEC 7816-4 section 8 puts the card capabilities in the
 historical bytes as a COMPACT-TLV object under tag '7', and its THIRD software
 function table carries "extended Lc and Le fields" in bit 7. CoreNFC hands us
 the historical bytes on `NFCISO7816Tag`, so the answer is available before the
 first command is sent and costs no round trip at all.

 IT FAILS CLOSED, AND THAT DIRECTION IS DELIBERATE. Every unparsable, absent,
 truncated or merely unfamiliar encoding returns "not supported". The cost of a
 false negative is that a capable chip is read slowly, which is exactly what we
 do today and is survivable. The cost of a false positive is a read that breaks
 in the middle on a document we may never see again. Those are not symmetrical
 and the code should not pretend they are.

 NOTHING HERE IDENTIFIES A PERSON. The historical bytes describe the chip
 platform, are identical across every document of a given model, and are not
 derived from anything the holder supplied. Even so, this type exposes the
 CONCLUSION and never the bytes, so no call site is tempted to log them.

 No em dashes, by design.
 */
public struct CardCapabilities: Equatable {

  /// Does the card accept extended Lc and Le fields? False whenever we could not
  /// establish that it does, which includes every parse failure.
  public let supportsExtendedLengthFields: Bool

  /// How many software function tables the card actually published. Recorded
  /// because "the card said nothing about extended length" and "the card said no"
  /// are different facts, and only the first is worth revisiting on a new model.
  public let softwareFunctionTableCount: Int

  /// The answer when there is nothing to read, or nothing we understand.
  public static let unknown = CardCapabilities(
    supportsExtendedLengthFields: false, softwareFunctionTableCount: 0)

  /**
   Read the card capabilities out of the ATS historical bytes.

   THE FIRST BYTE IS A CATEGORY INDICATOR AND IT DECIDES WHETHER THE REST IS
   PARSEABLE AT ALL, per ISO/IEC 7816-4 section 8.1.1:

   - `0x00`: COMPACT-TLV objects follow, and the LAST THREE bytes are a status
     indicator rather than TLV. Walking those three as TLV is how a parser
     invents a data object that is not there, so they are cut off first.
   - `0x80`: COMPACT-TLV objects follow to the end. A status indicator, if any,
     is itself one of them under tag '8'.
   - anything else: proprietary or reserved. NOT guessed at.

   Returns `unknown` rather than nil, so that a caller cannot accidentally treat
   "we could not tell" as an optional worth force unwrapping.
   */
  public static func parse(historicalBytes: [UInt8]) -> CardCapabilities {
    guard let category = historicalBytes.first else { return .unknown }

    let body: ArraySlice<UInt8>
    switch category {
    case 0x00:
      /* The three trailing status bytes are not TLV. A one byte historical
         string, or anything too short to hold both the indicator and the status,
         leaves nothing to walk. */
      guard historicalBytes.count > 4 else { return .unknown }
      body = historicalBytes[1..<(historicalBytes.count - 3)]
    case 0x80:
      guard historicalBytes.count > 1 else { return .unknown }
      body = historicalBytes[1...]
    default:
      return .unknown
    }

    guard let capabilities = firstCardCapabilities(in: body) else { return .unknown }

    /* THE THIRD TABLE IS OPTIONAL AND ITS ABSENCE IS AN ANSWER. A card publishing
       only the first or first two tables has said nothing about extended length,
       and per the fail closed rule above that is a no. */
    guard capabilities.count >= 3 else {
      return CardCapabilities(
        supportsExtendedLengthFields: false,
        softwareFunctionTableCount: capabilities.count)
    }

    /* ISO/IEC 7816-4 section 8, third software function table, bit 7.
       Bit 7 counting from 1 at the least significant bit is 0x40, and that is
       the whole of the claim this file makes about the standard. */
    let extendedLcLe: UInt8 = 0x40
    return CardCapabilities(
      supportsExtendedLengthFields: capabilities[2] & extendedLcLe == extendedLcLe,
      softwareFunctionTableCount: capabilities.count)
  }

  /**
   Walk COMPACT-TLV and return the value of the card capabilities object.

   COMPACT-TLV packs tag and length into ONE byte: the high nibble is the tag
   number, the low nibble is the length of the value that follows. Card
   capabilities is tag '7', so the byte is 0x71, 0x72 or 0x73 and the digit is
   both the length and, not by coincidence, the number of software function
   tables present.

   THE WALK REFUSES TO RUN OFF THE END. A length nibble that claims more bytes
   than remain is a malformed or misidentified historical string, and the answer
   to that is to stop, not to clamp and carry on reading whatever is adjacent.
   */
  private static func firstCardCapabilities(in body: ArraySlice<UInt8>) -> [UInt8]? {
    var index = body.startIndex
    while index < body.endIndex {
      let header = body[index]

      /* 0x00 and 0xFF are padding in a historical string, not tags. Treating
         0x00 as "tag 0, length 0" would loop forever on a padded card. */
      if header == 0x00 || header == 0xFF { return nil }

      let tag = header >> 4
      let length = Int(header & 0x0F)
      let valueStart = body.index(after: index)
      guard let valueEnd = body.index(
        valueStart, offsetBy: length, limitedBy: body.endIndex)
      else { return nil }

      if tag == 0x7 {
        return length == 0 ? nil : Array(body[valueStart..<valueEnd])
      }
      index = valueEnd
    }
    return nil
  }
}

//
//  FravashContentFailureTests.swift
//
//  fravash: proves that an unreadable portrait is classified as recoverable,
//  and that the classification is not vacuously true.
//

import Foundation
import XCTest
import OpenSSL

@testable import NFCPassportReader

final class FravashContentFailureTests: XCTestCase {

    /*
     The DG2 fixture from `DataGroupParsingTests.testDatagroup2ParsingJPEG2000`,
     with ONLY the ten byte JPEG 2000 signature at the end replaced. Every record
     length in front of it is therefore still correct, so the parser walks the
     whole structure successfully and fails at exactly one place: the image
     container it does not recognise. That is the failure a real document with an
     unsupported encoding produces, rather than a generically corrupt blob.
     */
    private let dg2WithUnknownImageFormat = "75617F61570201017F6082203FA1128002010081010282010087020101880200085F2E38464143003031300000002026000100002018000000000000000000010000000000000001000000000000000000000000DEADBEEFDEADBEEFDEAD"

    /// The good fixture, unchanged, so a failure below means the mutation and not
    /// a broken harness.
    private let dg2Valid = "75617F61570201017F6082203FA1128002010081010282010087020101880200085F2E38464143003031300000002026000100002018000000000000000000010000000000000001000000000000000000000000000C6A5020200D0A"

    /// CONTROL. If this ever fails, the fixture or the parser moved and every
    /// assertion below is meaningless.
    func testTheUnmodifiedFixtureStillParses() {
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: hexRepToBin(dg2Valid)))
    }

    /// A portrait in a container we do not support must be a CONTENT failure, so
    /// the read can continue and keep DG1 and the security object.
    func testUnreadablePortraitIsRecoverable() {
        let dgp = DataGroupParser()
        do {
            _ = try dgp.parseDG(data: hexRepToBin(dg2WithUnknownImageFormat))
            XCTFail("Expected an unrecognised image container to throw")
        } catch let error as NFCPassportReaderError {
            /* ASSERT THE CASE, NOT JUST THE BOOLEAN. A test satisfied by any
               error would pass if the parser started failing earlier for an
               unrelated reason, and would then be proving nothing about the
               portrait. */
            guard case .UnknownImageFormat = error else {
                XCTFail("Expected UnknownImageFormat, got \(error.value)")
                return
            }
            XCTAssertTrue(
                error.isContentFailure,
                "An unreadable portrait must not abort a read that already has DG1 and SOD")
        } catch {
            XCTFail("Expected NFCPassportReaderError, got \(error)")
        }
    }

    /**
     NEGATIVE CONTROL, and the reason this file is worth having.

     `isContentFailure` returning true for everything would satisfy the test
     above and would silently convert a lost tag into a passport with missing
     data groups. These are the errors that must stay fatal.
     */
    func testSessionFailuresAreNotRecoverable() {
        let fatal: [NFCPassportReaderError] = [
            .NoConnectedTag,
            .TagNotValid,
            .ConnectionError,
            .TimeOutError,
            .UserCanceled,
            .InvalidMRZKey,
            .ChipAuthenticationFailed,
            .UnableToUnprotectAPDU,
            .InvalidResponseChecksum,
        ]
        for error in fatal {
            XCTAssertFalse(
                error.isContentFailure,
                "\(error.value) must abort the read, not be skipped past")
        }
    }
}

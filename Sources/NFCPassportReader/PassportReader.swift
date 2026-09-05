//
//  PassportReader.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OSLog

#if !os(macOS)
import UIKit
import CoreNFC

@available(iOS 15, *)
public protocol PassportReaderTrackingDelegate: AnyObject {
    func nfcTagDetected()
    func readCardAccess(cardAccess: CardAccess)
    func paceStarted()
    func paceSucceeded()
    func paceFailed()
    func bacStarted()
    func bacSucceeded()
    func bacFailed()
}

@available(iOS 15, *)
extension PassportReaderTrackingDelegate {
    func nfcTagDetected() { /* default implementation */ }
    func readCardAccess(cardAccess: CardAccess) { /* default implementation */ }
    func paceStarted() { /* default implementation */ }
    func paceSucceeded() { /* default implementation */ }
    func paceFailed() { /* default implementation */ }
    func bacStarted() { /* default implementation */ }
    func bacSucceeded() { /* default implementation */ }
    func bacFailed() { /* default implementation */ }
}

@available(iOS 15, *)
public class PassportReader : NSObject {
    private typealias NFCCheckedContinuation = CheckedContinuation<NFCPassportModel, Error>
    private var nfcContinuation: NFCCheckedContinuation?

    public weak var trackingDelegate: PassportReaderTrackingDelegate?

    /**
     fravash: WHY iOS TORE THE SESSION DOWN, KEPT WHERE THE CALLER CAN STILL SEE IT.

     THE RACE THIS EXISTS TO SURVIVE. Two paths resume the same continuation and
     only one of them knows anything. `didInvalidateWithError` is handed the real
     reason by CoreNFC and maps it: 200 user cancelled, 201 session timeout,
     anything else `UnexpectedError`. Meanwhile the transceive that was in flight
     when the session died throws `NFCError` 103 immediately, lands in the generic
     catch in `didDetect`, and becomes `.Unknown(error)`. Whichever resumes first
     nils the continuation and the other is discarded.

     In practice the 103 wins, so the caller is told "Unknown error: Session
     invalidated" and the ANSWER, which is 201 timeout or 202 terminated
     unexpectedly or 203 system is busy, three different bugs with three different
     fixes, is thrown on the floor.

     THIS DOES NOT CHANGE WHICH ERROR IS THROWN, DELIBERATELY. Changing the winner
     of that race is a behaviour change and this is a diagnosis. The reason is
     merely recorded, before anything resumes, so a caller that has just caught a
     bare 103 can ask what actually happened.

     NIL IS A FINDING, NOT AN ABSENCE OF ONE. It is cleared at the start of every
     read, so a 103 with nothing here means nothing invalidated the session and it
     died some other way.

     NOTHING PERSONAL IS IN IT. A domain, an integer and CoreNFC's own sentence.
     */
    public struct SessionInvalidation {
        public let domain: String
        public let code: Int
        public let localizedDescription: String
    }

    public private(set) var lastSessionInvalidation: SessionInvalidation?

    /**
     fravash: what the chip published about itself, for the caller to record.

     MEASUREMENT ONLY. Nothing in this reader consults it. It is here so that a
     debug build can report, across real documents, whether extended length APDUs
     are available at all, since that answer decides whether a much larger piece
     of work is worth starting. Nil until a tag is connected, and cleared per read
     for the same reason `lastSessionInvalidation` is: a value left over from the
     previous attempt would be read as belonging to this one.
     */
    public private(set) var lastCardCapabilities: CardCapabilities?

    private var passport : NFCPassportModel = NFCPassportModel()
    
    private var readerSession: NFCTagReaderSession?
    private var currentlyReadingDataGroup : DataGroupId?
    
    private var dataGroupsToRead : [DataGroupId] = []
    private var readAllDatagroups = false
    private var skipSecureElements = true
    private var skipCA = false
    private var skipPACE = false
    
    // Extended mode is used for reading eMRTD's that support extended length APDUs
    private var useExtendedMode = false

    private var bacHandler : BACHandler?
    private var caHandler : ChipAuthenticationHandler?
    private var paceHandler : PACEHandler?
    private var mrzKey : String = ""
    private var aaChallenge: [UInt8]?
    private var dataAmountToReadOverride : Int? = nil
    
    private var scanCompletedHandler: ((NFCPassportModel?, NFCPassportReaderError?)->())!
    private var nfcViewDisplayMessageHandler: ((NFCViewDisplayMessage) -> String?)?
    private var masterListURL : URL?
    private var shouldNotReportNextReaderSessionInvalidationErrorUserCanceled : Bool = false

    // By default, Passive Authentication uses the new RFS5652 method to verify the SOD, but can be switched to use
    // the previous OpenSSL CMS verification if necessary
    public var passiveAuthenticationUsesOpenSSL : Bool = false

    /**
     fravash: data groups that may fail to PARSE without aborting the whole read.

     EMPTY BY DEFAULT, so existing callers keep the behaviour they have. A caller
     that has not thought about a missing data group should keep getting the
     abort rather than a quietly incomplete passport.

     Only CONTENT failures are tolerated, and only for the data groups named
     here. A lost tag, a broken secure messaging session or a failed
     authentication still aborts, whatever is in this list. See
     `NFCPassportReaderError.isContentFailure`.

     Anything skipped is recorded in `NFCPassportModel.dataGroupErrors`, so a
     caller can tell the difference between "this passport has no portrait" and
     "we could not read the portrait" and say the right thing to the person.

     DO NOT PUT DG1 OR SOD IN HERE. They carry the identity and the issuing
     state's signature, so a read that lost either has produced nothing worth
     having and should fail loudly.
     */
    public var tolerateContentFailuresIn : [DataGroupId] = []

    public init( masterListURL: URL? = nil ) {
        super.init()
        
        self.masterListURL = masterListURL
    }
    
    public func setMasterListURL( _ masterListURL : URL ) {
        self.masterListURL = masterListURL
    }
    
    // This function allows you to override the amount of data the TagReader tries to read from the NFC
    // chip. NOTE - this really shouldn't be used for production but is useful for testing as different
    // passports support different data amounts.
    // It appears that the most reliable is 0xA0 (160 chars) but some will support arbitary reads (0xFF or 256)
    public func overrideNFCDataAmountToRead( amount: Int ) {
        dataAmountToReadOverride = amount
    }
    
    public func readPassport( mrzKey : String, tags : [DataGroupId] = [], aaChallenge: [UInt8]? = nil, skipSecureElements : Bool = true, skipCA : Bool = false, skipPACE : Bool = false, useExtendedMode : Bool = false, customDisplayMessage : ((NFCViewDisplayMessage) -> String?)? = nil) async throws -> NFCPassportModel {
        
        self.passport = NFCPassportModel()
        /* fravash: cleared per read, so a reason left over from the previous
           attempt cannot be read as belonging to this one. */
        self.lastSessionInvalidation = nil
        self.lastCardCapabilities = nil
        self.mrzKey = mrzKey
        self.aaChallenge = aaChallenge
        self.skipCA = skipCA
        self.skipPACE = skipPACE
        self.useExtendedMode = useExtendedMode
        
        self.dataGroupsToRead.removeAll()
        self.dataGroupsToRead.append( contentsOf:tags)
        self.nfcViewDisplayMessageHandler = customDisplayMessage
        self.skipSecureElements = skipSecureElements
        self.currentlyReadingDataGroup = nil
        self.bacHandler = nil
        self.caHandler = nil
        self.paceHandler = nil
        
        // If no tags specified, read all
        if self.dataGroupsToRead.count == 0 {
            // Start off with .COM, will always read (and .SOD but we'll add that after), and then add the others from the COM
            self.dataGroupsToRead.append(contentsOf:[.COM, .SOD] )
            self.readAllDatagroups = true
        } else {
            // We are reading specific datagroups
            self.readAllDatagroups = false
        }
        
        guard NFCNDEFReaderSession.readingAvailable else {
            throw NFCPassportReaderError.NFCNotSupported
        }
        
        if NFCTagReaderSession.readingAvailable {
            readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.requestPresentPassport )
            readerSession?.begin()
        }
        
        return try await withCheckedThrowingContinuation({ (continuation: NFCCheckedContinuation) in
            self.nfcContinuation = continuation
        })
    }
}

@available(iOS 15, *)
extension PassportReader : NFCTagReaderSessionDelegate {
    // MARK: - NFCTagReaderSessionDelegate
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // If necessary, you may perform additional operations on session start.
        // At this point RF polling is enabled.
        Logger.passportReader.debug( "tagReaderSessionDidBecomeActive" )
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // If necessary, you may handle the error. Note session is no longer valid.
        // You must create a new session to restart RF polling.
        Logger.passportReader.debug( "tagReaderSession:didInvalidateWithError - \(error.localizedDescription)" )

        /* fravash: BEFORE ANYTHING ELSE IN THIS FUNCTION, and that ordering is the
           whole point. Every other statement here can resume the continuation and
           hand control back to a caller that will immediately want to know this.
           See `SessionInvalidation`. */
        let invalidationError = error as NSError
        self.lastSessionInvalidation = SessionInvalidation(
            domain: invalidationError.domain,
            code: invalidationError.code,
            localizedDescription: invalidationError.localizedDescription)

        self.readerSession?.invalidate()
        self.readerSession = nil

        if let readerError = error as? NFCReaderError, readerError.code == NFCReaderError.readerSessionInvalidationErrorUserCanceled
            && self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled {
            
            self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = false
        } else {
            var userError = NFCPassportReaderError.UnexpectedError
            if let readerError = error as? NFCReaderError {
                Logger.passportReader.error( "tagReaderSession:didInvalidateWithError - Got NFCReaderError - \(readerError.localizedDescription)" )
                switch (readerError.code) {
                case NFCReaderError.readerSessionInvalidationErrorUserCanceled:
                    Logger.passportReader.error( "     - User cancelled session" )
                    userError = NFCPassportReaderError.UserCanceled
                case NFCReaderError.readerSessionInvalidationErrorSessionTimeout:
                    Logger.passportReader.error("     - Session timeout")
                    userError = NFCPassportReaderError.TimeOutError
                default:
                    Logger.passportReader.error( "     - some other error - \(readerError.localizedDescription)" )
                    userError = NFCPassportReaderError.UnexpectedError
                }
            } else {
                Logger.passportReader.error( "tagReaderSession:didInvalidateWithError - Received error - \(error.localizedDescription)" )
            }
            nfcContinuation?.resume(throwing: userError)
            nfcContinuation = nil
        }
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Logger.passportReader.debug( "tagReaderSession:didDetect - found \(tags)" )
        if tags.count > 1 {
            Logger.passportReader.debug( "tagReaderSession:more than 1 tag detected! - \(tags)" )

            let errorMessage = NFCViewDisplayMessage.error(.MoreThanOneTagFound)
            self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.MoreThanOneTagFound)
            return
        }

        let tag = tags.first!
        var passportTag: NFCISO7816Tag
        switch tags.first! {
        case let .iso7816(tag):
            passportTag = tag
        default:
            Logger.passportReader.debug( "tagReaderSession:invalid tag detected!!!" )

            let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.TagNotValid)
            self.invalidateSession(errorMessage:errorMessage, error: NFCPassportReaderError.TagNotValid)
            return
        }
        
        Task { [passportTag] in
            do {
                try await session.connect(to: tag)
                
                Logger.passportReader.debug( "tagReaderSession:connected to tag - starting authentication" )
                self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(0) )
                
                let tagReader = TagReader(tag:passportTag)
                /* fravash: recorded the moment the tag is connected, before any
                   command is sent, because it comes from the ATS rather than from
                   the chip's files and costs no round trip. */
                self.lastCardCapabilities = tagReader.cardCapabilities

                if let newAmount = self.dataAmountToReadOverride {
                    tagReader.overrideDataAmountToRead(newAmount: newAmount)
                }
                
                tagReader.progress = { [unowned self] (progress) in
                    if let dgId = self.currentlyReadingDataGroup {
                        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, progress) )
                    } else {
                        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(progress) )
                    }
                }
                
                let passportModel = try await self.startReading( tagReader : tagReader)
                nfcContinuation?.resume(returning: passportModel)
                nfcContinuation = nil

                
            } catch let error as NFCPassportReaderError {
                let errorMessage = NFCViewDisplayMessage.error(error)
                self.invalidateSession(errorMessage: errorMessage, error: error)
            } catch {
                Logger.passportReader.debug( "tagReaderSession:failed to connect to tag - \(error.localizedDescription)" )

                // .readerTransceiveErrorTagResponseError is thrown when a "connection lost" scenario is forced by moving the phone away from the NFC chip
                // .readerTransceiveErrorTagConnectionLost is never thrown for this scenario, but added for the sake of completeness
                /* fravash: THREE MORE TRANSCEIVE ERRORS, AND THIS IS A SENTENCE FIX
                   RATHER THAN A BUG FIX. It must not be mistaken for one.

                   Only 100 and 102 were listed, so 101 retry exceeded, 103 session
                   invalidated and 104 tag not connected all fell through to
                   `.Unknown(error)`. Downstream, `ReadFailure` has no arm for
                   `.Unknown`, so a real passport that lost its session mid read
                   showed its holder "Something went wrong while reading the
                   document", the most generic sentence we have, when the honest
                   one is that contact was lost. All five are the same thing to a
                   person: the phone and the document stopped talking.

                   IT DOES NOT MAKE THE READ WORK. The session still dies. This
                   only stops us describing it as an unknown internal error. */
                if let nfcError = error as? NFCReaderError,
                   nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagResponseError.rawValue ||
                    nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagConnectionLost.rawValue ||
                    nfcError.errorCode == NFCReaderError.readerTransceiveErrorRetryExceeded.rawValue ||
                    nfcError.errorCode == NFCReaderError.readerTransceiveErrorSessionInvalidated.rawValue ||
                    nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagNotConnected.rawValue {
                    let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.ConnectionError)
                    self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.ConnectionError)
                } else {
                    let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.Unknown(error))
                    self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.Unknown(error))
                }
            }
        }
    }
    
    func updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage ) {
        self.readerSession?.alertMessage = self.nfcViewDisplayMessageHandler?(alertMessage) ?? alertMessage.description
    }
}

@available(iOS 15, *)
extension PassportReader {
    
    func startReading(tagReader : TagReader) async throws -> NFCPassportModel {
        trackingDelegate?.nfcTagDetected()

        if !skipPACE {
            do {
                trackingDelegate?.paceStarted()

                let data = try await tagReader.readCardAccess()
                Logger.passportReader.debug( "Read CardAccess - data \(binToHexRep(data))" )
                let cardAccess = try CardAccess(data)
                passport.cardAccess = cardAccess

                trackingDelegate?.readCardAccess(cardAccess: cardAccess)

                Logger.passportReader.info( "Starting Password Authenticated Connection Establishment (PACE)" )
                 
                let paceHandler = try PACEHandler( cardAccess: cardAccess, tagReader: tagReader )
                try await paceHandler.doPACE(mrzKey: mrzKey )
                passport.PACEStatus = .success
                Logger.passportReader.debug( "PACE Succeeded" )

                trackingDelegate?.paceSucceeded()
            } catch {
                trackingDelegate?.paceFailed()

                passport.PACEStatus = .failed
                Logger.passportReader.error( "PACE Failed - falling back to BAC" )
            }
            
            _ = try await tagReader.selectPassportApplication()
        }
        
        // If either PACE isn't supported, we failed whilst doing PACE or we didn't even attempt it, then fall back to BAC
        if passport.PACEStatus != .success {
            do {
                trackingDelegate?.bacStarted()
                try await doBACAuthentication(tagReader : tagReader)
                trackingDelegate?.bacSucceeded()
            } catch {
                trackingDelegate?.bacFailed()
                throw error
            }
        }
        
        // Now to read the datagroups
        try await readDataGroups(tagReader: tagReader)

        try await doActiveAuthenticationIfNeccessary(tagReader : tagReader)

        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.successfulRead)
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate()

        // If we have a masterlist url set then use that and verify the passport now
        self.passport.verifyPassport(masterListURL: self.masterListURL, useCMSVerification: self.passiveAuthenticationUsesOpenSSL)

        return self.passport
    }
    
    
    func doActiveAuthenticationIfNeccessary( tagReader : TagReader) async throws {
        guard self.passport.activeAuthenticationSupported else {
            return
        }
        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.activeAuthentication)

        Logger.passportReader.info( "Performing Active Authentication" )

        let challenge = aaChallenge ?? generateRandomUInt8Array(8)
        Logger.passportReader.debug( "Generated Active Authentication challange - \(binToHexRep(challenge))")
        let response = try await tagReader.doInternalAuthentication(challenge: challenge, useExtendedMode: useExtendedMode)
        self.passport.verifyActiveAuthentication( challenge:challenge, signature:response.data )
    }
    

    func doBACAuthentication(tagReader : TagReader) async throws {
        self.currentlyReadingDataGroup = nil

        Logger.passportReader.info( "Starting Basic Access Control (BAC)" )
        
        self.passport.BACStatus = .failed

        self.bacHandler = BACHandler( tagReader: tagReader )
        try await bacHandler?.performBACAndGetSessionKeys( mrzKey: mrzKey )
        Logger.passportReader.info( "Basic Access Control (BAC) - SUCCESS!" )

        self.passport.BACStatus = .success
    }

    func readDataGroups( tagReader: TagReader ) async throws {
        
        // Read COM
        var DGsToRead = [DataGroupId]()

        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(.COM, 0) )
        
        if let com = try await readDataGroup(tagReader:tagReader, dgId:.COM) as? COM {
            self.passport.addDataGroup( .COM, dataGroup:com )
            self.addDatagroupsToRead(com: com, to: &DGsToRead)
        }
        
        if DGsToRead.contains( .DG14 ) {
            
            if !skipCA {
                // If we have been explicitly asked to read DG14 and we will be remove it from the list as we are reading it now.
                DGsToRead.removeAll { $0 == .DG14 }

                // Do Chip Authentication
                if let dg14 = try await readDataGroup(tagReader:tagReader, dgId:.DG14) as? DataGroup14 {
                    self.passport.addDataGroup( .DG14, dataGroup:dg14 )
                    let caHandler = ChipAuthenticationHandler(dg14: dg14, tagReader: tagReader)
                     
                    if caHandler.isChipAuthenticationSupported {
                        do {
                            // Do Chip authentication and then continue reading datagroups
                            try await caHandler.doChipAuthentication()
                            self.passport.chipAuthenticationStatus = .success
                        } catch {
                            Logger.passportReader.info( "Chip Authentication failed - re-establishing BAC")
                            self.passport.chipAuthenticationStatus = .failed
                            
                            // Failed Chip Auth, need to re-establish BAC
                            try await doBACAuthentication(tagReader: tagReader)
                        }
                    }
                }
            }
        }

        // If we are skipping secure elements then remove .DG3 and .DG4
        if self.skipSecureElements {
            DGsToRead = DGsToRead.filter { $0 != .DG3 && $0 != .DG4 }
        }

        if self.readAllDatagroups != true {
            DGsToRead = DGsToRead.filter { dataGroupsToRead.contains($0) }
        }
        for dgId in DGsToRead {
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )
            /* fravash: ONE UNPARSABLE DATA GROUP USED TO COST THE WHOLE READ.
               This loop was unguarded, so any failure on any data group threw out
               of `readDataGroups` and aborted everything, including the data
               groups that had already been read successfully.

               That is right for a lost tag and wrong for an unreadable portrait.
               ICAO permits both JPEG and JPEG 2000 in DG2, and is migrating DG2
               from ISO/IEC 19794-5 to 39794-5 (States may issue either until
               2030), so a document this library cannot render is not exotic, it
               is the normal near future. Before this change, such a passport
               could not be enrolled AT ALL, and the person saw a generic failure
               rather than "we could not read the photo".

               THE TOLERANCE IS OPT IN AND NAMES ITS DATA GROUPS. Silently
               widening the default would change behaviour for every existing
               caller, and a caller that has not thought about a missing data
               group should keep getting the abort. */
            do {
                if let dg = try await readDataGroup(tagReader:tagReader, dgId:dgId) {
                    self.passport.addDataGroup( dgId, dataGroup:dg )
                }
            } catch let error as NFCPassportReaderError where
                        tolerateContentFailuresIn.contains(dgId) && error.isContentFailure {
                /* SAFE TO CONTINUE, and the reason is specific rather than
                   optimistic: `parseDG` runs on bytes the APDU exchange already
                   returned, so secure messaging is still established and the next
                   data group reads normally. A session failure has no such
                   guarantee, which is why `isContentFailure` gates this. */
                Logger.passportReader.warning( "Tolerating unparsable \(dgId.getName()) - \(error.value)" )
                self.passport.addDataGroupError( dgId, error: error )
            }
        }
    }
    
    func readDataGroup( tagReader : TagReader, dgId : DataGroupId ) async throws -> DataGroup?  {

        self.currentlyReadingDataGroup = dgId
        Logger.passportReader.info( "Reading tag - \(dgId.getName())" )
        var readAttempts = 0
        var nfcPassportReaderError: NFCPassportReaderError
        
        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )

        repeat {
            do {
                let response = try await tagReader.readDataGroup(dataGroup:dgId)
                let dg = try DataGroupParser().parseDG(data: response)
                return dg
            } catch let error as NFCPassportReaderError {
                Logger.passportReader.error( "TagError reading tag - \(error)" )
                nfcPassportReaderError = error

                // OK we had an error - depending on what happened, we may want to try to re-read this
                // E.g. we failed to read the last Datagroup because its protected and we can't
                let errMsg = error.value
                Logger.passportReader.error( "ERROR - \(errMsg)" )
                var redoBAC = false
                if errMsg == "Session invalidated" || errMsg == "Class not supported" || errMsg == "Tag connection lost" || errMsg == "Tag response error / no response" {
                    // Check if we have done Chip Authentication, if so, set it to nil and try to redo BAC
                    if self.caHandler != nil {
                        self.caHandler = nil
                        redoBAC = true
                    } else {
                        // Can't go any more!
                        throw error
                    }
                } else if errMsg == "Security status not satisfied" || errMsg == "File not found" {
                    // Can't read this element as we aren't allowed - remove it and return out so we re-do BAC
                    self.dataGroupsToRead.removeFirst()
                    redoBAC = true
                } else if errMsg == "SM data objects incorrect" || errMsg == "Class not supported" {
                    // Can't read this element security objects now invalid - and return out so we re-do BAC
                    redoBAC = true
                } else if errMsg.hasPrefix( "Wrong length" ) || errMsg.hasPrefix( "End of file" ) {  // Should now handle errors 0x6C xx, and 0x67 0x00
                    // OK passport can't handle max length so drop it down
                    tagReader.reduceDataReadingAmount()
                    redoBAC = true
                } else if errMsg == "UnsupportedDataGroup" {
                    // OK, this DataGroup is not supported, lets skip it
                    Logger.passportReader.debug("Unsupported DataGroup - \(dgId.rawValue)")
                    return nil
                }
                
                if redoBAC {
                    // Redo BAC and try again
                    try await doBACAuthentication(tagReader : tagReader)
                } else {
                    // Some other error lets have another try
                }
            }
            readAttempts += 1
        } while ( readAttempts < 2 )

        // The error will be thrown after n attempts
        throw nfcPassportReaderError
    }

    func invalidateSession(errorMessage: NFCViewDisplayMessage, error: NFCPassportReaderError) {
        // Mark the next 'invalid session' error as not reportable (we're about to cause it by invalidating the
        // session). The real error is reported back with the call to the completed handler
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate(errorMessage: self.nfcViewDisplayMessageHandler?(errorMessage) ?? errorMessage.description)
        nfcContinuation?.resume(throwing: error)
        nfcContinuation = nil
    }
    
    internal func addDatagroupsToRead(com: COM, to DGsToRead: inout [DataGroupId]) {
        DGsToRead += com.dataGroupsPresent.compactMap { DataGroupId.getIDFromName(name:$0) }
        DGsToRead.removeAll { $0 == .COM }
        
        // SOD should not be present in COM, but just in case we check before adding it so its not read twice
        if !DGsToRead.contains(.SOD) { DGsToRead.insert(.SOD, at: 0) }
    }
}
#endif

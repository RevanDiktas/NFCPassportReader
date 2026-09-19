//
//  NFCPassportModel.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 29/10/2019.
//


import Foundation
import OSLog

#if os(iOS)
import UIKit
#endif


public enum PassportAuthenticationStatus {
    case notDone
    case success
    case failed
}

/**
 fravash: one row of EF.SOD's DataGroupHashValues, exactly as the document
 carries it.

 DELIBERATELY NOT KEYED BY `DataGroupId`. The number is what gets committed to,
 and the enum cannot carry it faithfully: `dgList` maps 0 to `.COM` and 17 to
 `.SOD`, has nothing at all above 17, and a consumer turning a case back into a
 number collapses everything it does not recognise onto 0. Two SOD rows can land
 on one key that way, and the number recorded can differ from the number another
 implementation reads off the same bytes. The reference implementation this must
 agree with byte for byte, `packages/eid/src/sod.ts`, carries the raw ASN.1
 INTEGER through untouched, so this does too.

 A row here is what was PARSED, not what was verified. See `sodDataGroupHashes`.
 */
public struct SodDataGroupHash : Equatable {
    /// The raw INTEGER from the SOD, unmapped and unvalidated.
    public let dataGroupNumber : Int
    /// Hex, exactly as parsed, neither case normalised nor length checked.
    public let hash : String

    public init( dataGroupNumber: Int, hash: String ) {
        self.dataGroupNumber = dataGroupNumber
        self.hash = hash
    }
}

@available(iOS 13, macOS 10.15, *)
public class NFCPassportModel {
    
    public private(set) lazy var documentType : String = { return String( passportDataElements?["5F03"]?.first ?? "?" ) }()
    public private(set) lazy var documentSubType : String = { return String( passportDataElements?["5F03"]?.last ?? "?" ) }()
    public private(set) lazy var documentNumber : String = { return (passportDataElements?["5A"] ?? "?").replacingOccurrences(of: "<", with: "" ) }()
    public private(set) lazy var issuingAuthority : String = { return passportDataElements?["5F28"] ?? "?" }()
    public private(set) lazy var documentExpiryDate : String = { return passportDataElements?["59"] ?? "?" }()
    public private(set) lazy var dateOfBirth : String = { return passportDataElements?["5F57"] ?? "?" }()
    public private(set) lazy var gender : String = { return passportDataElements?["5F35"] ?? "?" }()
    public private(set) lazy var nationality : String = { return passportDataElements?["5F2C"] ?? "?" }()
    public private(set) lazy var optionalData : String = { return passportDataElements?["53"] ?? "?" }()

    public private(set) lazy var lastName : String = {
        return names[0].replacingOccurrences(of: "<", with: " " )
    }()
    
    public private(set) lazy var firstName : String = {
        var name = ""
        for i in 1 ..< names.count {
            let fn = names[i].replacingOccurrences(of: "<", with: " " ).trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            name += fn + " "
        }
        return name.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
    }()
    
    public private(set) lazy var passportMRZ : String = { return passportDataElements?["5F1F"] ?? "NOT FOUND" }()
    
    // Extract fields from DG11 if present
    private lazy var names : [String] = {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let fullName = dg11.fullName?.components(separatedBy: "<<") else { return (passportDataElements?["5B"] ?? "?").components(separatedBy: "<<") }
        return fullName
    }()
    
    public private(set) lazy var placeOfBirth : String? = {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let placeOfBirth = dg11.placeOfBirth else { return nil }
        return placeOfBirth
    }()
    
    /// residence address
    public private(set) lazy var residenceAddress : String? = {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let address = dg11.address else { return nil }
        return address
    }()
    
    /// phone number
    public private(set) lazy var phoneNumber : String? = {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let telephone = dg11.telephone else { return nil }
        return telephone
    }()
    
    /// personal number
    public private(set) lazy var personalNumber : String? = {
        if let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
           let personalNumber = dg11.personalNumber { return personalNumber }
        
        return (passportDataElements?["53"] ?? "?").replacingOccurrences(of: "<", with: "" )
    }()
    
    /// face image info
    public private(set) lazy var faceImageInfo : FaceImageInfo? = {
        guard let dg2 = dataGroupsRead[.DG2] as? DataGroup2 else { return nil }
        
        return FaceImageInfo.from(dg2: dg2)
    }()

    public private(set) lazy var documentSigningCertificate : X509Wrapper? = {
        return certificateSigningGroups[.documentSigningCertificate]
    }()

    public private(set) lazy var countrySigningCertificate : X509Wrapper? = {
        return certificateSigningGroups[.issuerSigningCertificate]
    }()
    
    // Extract data from COM
    public private(set) lazy var LDSVersion : String = {
        guard let com = dataGroupsRead[.COM] as? COM else { return "Unknown" }
        return com.version
    }()
    
    
    public private(set) lazy var dataGroupsPresent : [String] = {
        guard let com = dataGroupsRead[.COM] as? COM else { return [] }
        return com.dataGroupsPresent
    }()
    
    // Parsed datagroup hashes
    public private(set) var dataGroupsAvailable = [DataGroupId]()
    public private(set) var dataGroupsRead : [DataGroupId:DataGroup] = [:]
    public private(set) var dataGroupHashes = [DataGroupId: DataGroupHash]()

    /**
     fravash: the COMPLETE hash table the issuing state signed, in the order the
     SOD lists it, duplicates included, independent of which data groups this
     read recovered.

     `dataGroupHashes` ABOVE IS NOT THIS TABLE, THOUGH IT LOOKS LIKE IT. It is
     built by walking `dataGroupsRead`, so its keys are the groups this read
     happened to get and parse, minus SOD and COM. A tolerated parse failure
     (see `dataGroupErrors`) drops a group from `dataGroupsRead` and therefore
     from `dataGroupHashes`, on a document whose SOD still signs it. Anything
     deriving a STABLE value from a document must commit over the signed table,
     which is this one, and never over a set that depends on how the read went.

     NOT DEDUPED, NOT SORTED, NOT FILTERED. A repeated data group number is a
     forgery signal: two candidate hashes for one group let a lenient verifier
     match either. It is left in rather than resolved here, so that a caller can
     refuse it, and so that this stays a faithful record rather than a judgement.
     A number outside the range this parser can name is kept too, because the
     state signed it whether or not we recognise it.

     POPULATED DOES NOT MEAN VERIFIED. It is assigned as soon as the SOD's
     content parses, which is BEFORE the tamper comparison runs and before that
     comparison can throw, and `verifyPassport` swallows the throw into
     `verificationErrors`. A document that failed passive authentication still
     leaves a full table here. Check `passportCorrectlySigned` and
     `passportDataNotTampered` before trusting it for anything.

     Empty until `verifyPassport` has run.
     */
    public private(set) var sodDataGroupHashes : [SodDataGroupHash] = []

    /**
     fravash: the digest algorithm the SOD declares, as
     `parseSODSignatureContent` returns it: "SHA1", "SHA224", "SHA256", "SHA384"
     or "SHA512".

     Carried alongside `sodDataGroupHashes` because those hashes are meaningless
     without it: the same document under a different algorithm is a different
     table. Assigned at the same moment and under the same caveat, so read
     `passportCorrectlySigned` and `passportDataNotTampered` first.

     Empty until `verifyPassport` has run.
     */
    public private(set) var sodHashAlgorithm : String = ""

    public internal(set) var cardAccess : CardAccess?
    public internal(set) var BACStatus : PassportAuthenticationStatus = .notDone
    public internal(set) var PACEStatus : PassportAuthenticationStatus = .notDone
    public internal(set) var chipAuthenticationStatus : PassportAuthenticationStatus = .notDone

    public private(set) var passportCorrectlySigned : Bool = false
    public private(set) var documentSigningCertificateVerified : Bool = false
    public private(set) var passportDataNotTampered : Bool = false
    public private(set) var activeAuthenticationPassed : Bool = false
    public private(set) var activeAuthenticationChallenge : [UInt8] = []
    public private(set) var activeAuthenticationSignature : [UInt8] = []
    public private(set) var verificationErrors : [Error] = []

    /**
     fravash: data groups whose bytes arrived but could not be parsed.

     A READ THAT SKIPS SOMETHING MUST SAY SO. Tolerating an unparsable data group
     stops one bad portrait costing a whole enrolment, but a tolerance nobody can
     see is worse than the abort it replaced: the caller would render a confident
     result over a passport it only partly understood. Anything in here is a
     thing we did not get, named, so a caller can decide what to tell the person.

     Empty is the normal case and means every requested data group parsed.
     */
    public private(set) var dataGroupErrors : [DataGroupId: Error] = [:]

    public var isPACESupported : Bool {
        get {
            if cardAccess?.paceInfo != nil {
                return true
            } else {
                // We may not have stored the cardAccess so check the DG14
                if let dg14 = dataGroupsRead[.DG14] as? DataGroup14,
                   (dg14.securityInfos.filter { ($0 as? PACEInfo) != nil }).count > 0 {
                    return true
                }
                return false
            }
        }
    }
    
    public var isChipAuthenticationSupported : Bool {
        get {
            if let dg14 = dataGroupsRead[.DG14] as? DataGroup14,
               (dg14.securityInfos.filter { ($0 as? ChipAuthenticationPublicKeyInfo) != nil }).count > 0 {
                
                return true
            } else {
                return false
            }
        }
    }
    
#if os(iOS)
    public var passportImage : UIImage? {
        guard let dg2 = dataGroupsRead[.DG2] as? DataGroup2 else { return nil }
        
        return dg2.getImage()
    }

    public var signatureImage : UIImage? {
        guard let dg7 = dataGroupsRead[.DG7] as? DataGroup7 else { return nil }
        
        return dg7.getImage()
    }
#endif

    public var activeAuthenticationSupported : Bool {
        guard let dg15 = dataGroupsRead[.DG15] as? DataGroup15 else { return false }
        if dg15.ecdsaPublicKey != nil || dg15.rsaPublicKey != nil {
            return true
        }
        return false
    }

    private var certificateSigningGroups : [CertificateType:X509Wrapper] = [:]

    private var passportDataElements : [String:String]? {
        guard let dg1 = dataGroupsRead[.DG1] as? DataGroup1 else { return nil }
        
        return dg1.elements
    }
        
    
    public init() {
        
    }
    
    public init( from dump: [String:String] ) {
        var AAChallenge : [UInt8]?
        var AASignature : [UInt8]?
        for (key,value) in dump {
            if let data = Data(base64Encoded: value) {
                let bin = [UInt8](data)
                if key == "AASignature" {
                    AASignature = bin
                } else if key == "AAChallenge" {
                    AAChallenge = bin
                } else {
                    do {
                        let dg = try DataGroupParser().parseDG(data: bin)
                        let dgId = DataGroupId.getIDFromName(name:key)
                        self.addDataGroup( dgId, dataGroup:dg )
                    } catch {
                        Logger.passportReader.error("Failed to import Datagroup - \(key) from dump - \(error)" )
                    }
                }
            }
        }

        // See if we have Active Auth info in the dump
        if let challenge = AAChallenge, let signature = AASignature {
            verifyActiveAuthentication(challenge: challenge, signature: signature)
        }
    }
    
    public func addDataGroup(_ id : DataGroupId, dataGroup: DataGroup ) {
        self.dataGroupsRead[id] = dataGroup
        if id != .COM && id != .SOD {
            self.dataGroupsAvailable.append( id )
        }
    }

    /// fravash: record that a data group was requested, arrived, and could not be
    /// parsed. It is deliberately NOT added to `dataGroupsAvailable`: it is not
    /// available, and a caller iterating that list must not see it.
    public func addDataGroupError(_ id : DataGroupId, error: Error ) {
        self.dataGroupErrors[id] = error
    }

    public func getDataGroup( _ id : DataGroupId ) -> DataGroup? {
        return dataGroupsRead[id]
    }

    /// Dumps the passport data
    /// - Parameters:
    ///    selectedDataGroups - the Data Groups to be exported (if they are present in the passport)
    ///    includeActiveAutheticationData - Whether to include the Active Authentication challenge and response (if supported and retrieved)
    /// - Returns: dictionary of DataGroup ids and Base64 encoded data
    public func dumpPassportData( selectedDataGroups : [DataGroupId], includeActiveAuthenticationData : Bool = false) -> [String:String] {
        var ret = [String:String]()
        for dg in selectedDataGroups {
            if let dataGroup = self.dataGroupsRead[dg] {
                let val = Data(dataGroup.data)
                let base64 = val.base64EncodedString()
                ret[dg.getName()] = base64
            }
        }
        if includeActiveAuthenticationData && self.activeAuthenticationSupported {
            ret["AAChallenge"] = Data(activeAuthenticationChallenge).base64EncodedString()
            ret["AASignature"] = Data(activeAuthenticationSignature).base64EncodedString()
        }
        return ret
    }

    public func getHashesForDatagroups( hashAlgorythm: String ) -> [DataGroupId:[UInt8]]  {
        var ret = [DataGroupId:[UInt8]]()
        
        for (key, value) in dataGroupsRead {
            if hashAlgorythm == "SHA1" {
                ret[key] = calcSHA1Hash(value.body)
            } else if hashAlgorythm == "SHA224" {
                ret[key] = calcSHA224Hash(value.body)
            } else if hashAlgorythm == "SHA256" {
                ret[key] = calcSHA256Hash(value.body)
            } else if hashAlgorythm == "SHA384" {
                ret[key] = calcSHA384Hash(value.body)
            } else if hashAlgorythm == "SHA512" {
                ret[key] = calcSHA512Hash(value.body)
            }
        }
        
        return ret
    }
    
            
    /// This method performs the passive authentication
    /// Passive Authentication : Two Parts:
    /// Part 1 - Has the SOD (Security Object Document) been signed by a valid country signing certificate authority (CSCA)?
    /// Part 2 - has it been tampered with (e.g. hashes of Datagroups match those in the SOD?
    ///        guard let sod = model.getDataGroup(.SOD) else { return }
    ///
    /// - Parameter masterListURL: the path to the masterlist to try to verify the document signing certiifcate in the SOD
    /// - Parameter useCMSVerification: Should we use OpenSSL CMS verification to verify the SOD content
    ///         is correctly signed by the document signing certificate OR should we do this manully based on RFC5652
    ///         CMS fails under certain circumstances (e.g. hashes are SHA512 whereas content is signed with SHA256RSA).
    ///         Currently defaulting to manual verification - hoping this will replace the CMS verification totally
    ///         CMS Verification currently there just in case
    public func verifyPassport( masterListURL: URL?, useCMSVerification : Bool = false ) {
        if let masterListURL = masterListURL {
            do {
                try validateAndExtractSigningCertificates( masterListURL: masterListURL )
            } catch let error {
                verificationErrors.append( error )
            }
        }
        
        do {
            try ensureReadDataNotBeenTamperedWith( useCMSVerification : useCMSVerification )
        } catch let error {
            verificationErrors.append( error )
        }
    }
    
    public func verifyActiveAuthentication( challenge: [UInt8], signature: [UInt8] ) {
        self.activeAuthenticationChallenge = challenge
        self.activeAuthenticationSignature = signature
        
        Logger.passportReader.debug( "Active Authentication")
        Logger.passportReader.debug( "   challange - \(binToHexRep(challenge))")
        Logger.passportReader.debug( "   signature - \(binToHexRep(signature))")

        // Get AA Public key
        self.activeAuthenticationPassed = false
        guard  let dg15 = self.dataGroupsRead[.DG15] as? DataGroup15 else { return }
        if let rsaKey = dg15.rsaPublicKey {
            do {
                var decryptedSig = try OpenSSLUtils.decryptRSASignature(signature: Data(signature), pubKey: rsaKey)
                
                // Decrypted signature compromises of header (6A), Message, Digest hash, Trailer
                // Trailer can be 1 byte (BC - SHA-1 hash) or 2 bytes (xxCC) - where xx identifies the hash algorithm used
                
                // if the last byte of the digest is 0xBC, then this uses dedicated hash function 3 (SHA-1),
                // If the last byte is 0xCC, then the preceding byte tells you which hash function
                // should be used (currently not yet implemented!)
                // See ISO/IEC9796-2 for details on the verification and ISO/IEC 10118-3 for the dedicated hash functions!
                var hashTypeByte = decryptedSig.popLast() ?? 0x00
                if hashTypeByte == 0xCC {
                    hashTypeByte = decryptedSig.popLast() ?? 0x00
                }
                var hashType : String = ""
                var hashLength = 0

                switch hashTypeByte {
                    case 0xBC, 0x33:
                        hashType = "SHA1"
                        hashLength = 20  // 160 bits for SHA-1 -> 20 bytes
                    case 0x34:
                        hashType = "SHA256"
                        hashLength = 32  // 256 bits for SHA-256 -> 32 bytes
                    case 0x35:
                        hashType = "SHA512"
                        hashLength = 64  // 512 bits for SHA-512 -> 64 bytes
                    case 0x36:
                        hashType = "SHA384"
                        hashLength = 48  // 384 bits for SHA-384 -> 48 bytes
                    case 0x38:
                        hashType = "SHA224"
                        hashLength = 28  // 224 bits for SHA-224 -> 28 bytes
                    default:
                        Logger.passportReader.error( "Error identifying Active Authentication RSA message digest hash algorithm" )
                        return
                }
                
                let message = [UInt8](decryptedSig[1 ..< (decryptedSig.count-hashLength)])
                let digest = [UInt8](decryptedSig[(decryptedSig.count-hashLength)...])

                // Concatenate the challenge to the end of the message
                let fullMsg = message + challenge
                
                // Then generate the hash
                let msgHash : [UInt8] = try calcHash(data: fullMsg, hashAlgorithm: hashType)
                
                // Check hashes match
                if msgHash == digest {
                    self.activeAuthenticationPassed = true
                    Logger.passportReader.debug( "Active Authentication (RSA) successful" )
                } else {
                    Logger.passportReader.error( "Error verifying Active Authentication RSA signature - Hash doesn't match" )
                }
            } catch {
                Logger.passportReader.error( "Error verifying Active Authentication RSA signature - \(error)" )
            }
        } else if let ecdsaPublicKey = dg15.ecdsaPublicKey {
            var digestType = ""
            if let dg14 = dataGroupsRead[.DG14] as? DataGroup14,
               let aa = dg14.securityInfos.compactMap({ $0 as? ActiveAuthenticationInfo }).first {
                digestType = aa.getSignatureAlgorithmOIDString() ?? ""
            }
            
            if OpenSSLUtils.verifyECDSASignature( publicKey:ecdsaPublicKey, signature: signature, data: challenge, digestType: digestType ) {
                self.activeAuthenticationPassed = true
                Logger.passportReader.debug( "Active Authentication (ECDSA) successful" )
            } else {
                Logger.passportReader.error( "Error verifying Active Authentication ECDSA signature" )
            }
        }
    }
    
    // Check if signing certificate is on the revocation list
    // We do this by trying to build a trust chain of the passport certificate against the ones in the revocation list
    // and if we are successful then its been revoked.
    // NOTE - NOT USED YET AS NOT ABLE TO TEST
    func hasCertBeenRevoked( revocationListURL : URL ) -> Bool {
        var revoked = false
        do {
            try validateAndExtractSigningCertificates( masterListURL: revocationListURL )
            
            // Certificate chain found - which means certificate is on revocation list
            revoked = true
        } catch {
            // No chain found - certificate not revoked
        }
        
        return revoked
    }

    private func validateAndExtractSigningCertificates( masterListURL: URL ) throws {
        self.passportCorrectlySigned = false
        
        guard let sod = getDataGroup(.SOD) else {
            throw PassiveAuthenticationError.SODMissing("No SOD found" )
        }

        let data = Data(sod.body)
        let cert = try OpenSSLUtils.getX509CertificatesFromPKCS7( pkcs7Der: data ).first!
        self.certificateSigningGroups[.documentSigningCertificate] = cert

        let rc = OpenSSLUtils.verifyTrustAndGetIssuerCertificate( x509:cert, CAFile: masterListURL )
        switch rc {
        case .success(let csca):
            self.certificateSigningGroups[.issuerSigningCertificate] = csca
        case .failure(let error):
            throw error
        }
                
        Logger.passportReader.debug( "Passport passed SOD Verification" )
        self.passportCorrectlySigned = true

    }

    private func ensureReadDataNotBeenTamperedWith( useCMSVerification: Bool ) throws  {
        guard let sod = getDataGroup(.SOD) as? SOD else {
            throw PassiveAuthenticationError.SODMissing("No SOD found" )
        }

        // Get SOD Content and verify that its correctly signed by the Document Signing Certificate
        var signedData : Data
        documentSigningCertificateVerified = false
        do {
            if useCMSVerification {
                signedData = try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod)
            } else {
                signedData = try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod)
            }
            documentSigningCertificateVerified = true
        } catch {
            signedData = try sod.getEncapsulatedContent()
        }
                
        // Now Verify passport data by comparing compare Hashes in SOD against
        // computed hashes to ensure data not been tampered with
        passportDataNotTampered = false
        /* fravash: THE BYTES, NOT A RENDERING OF THEM. This used to be
           `OpenSSLUtils.ASN1Parse(data:)` followed by a scrape of the human
           readable dump it returns. See `parseSODSignatureContent`. */
        let (sodHashAlgorythm, sodHashes, sodRows) = try parseSODSignatureContent( signedData )

        /* fravash: KEEP WHAT THE STATE SIGNED, BEFORE THE LOOP NARROWS IT.
           The full signed table has been a local that this function threw away.
           The loop below reduces it to the groups actually read, which is the
           right input for a tamper check and the wrong one for anything that
           must be stable across reads. Recorded here, before the comparison, so
           the record is of what the SOD SAID rather than of what this read
           managed to confirm. Refusing to derive from an unverified document is
           the caller's job and the doc comments say so. */
        self.sodDataGroupHashes = sodRows
        self.sodHashAlgorithm = sodHashAlgorythm

        /* fravash: REFUSED HERE RATHER THAN INSIDE THE PARSER, so the rows
           survive the refusal. The parser used to throw on an empty mapped
           table before `sodDataGroupHashes` had been assigned, so a document
           that failed this check left NO readable record of what its SOD
           actually said, which is precisely the document somebody needs the
           record for. Assign first, refuse second. */
        if sodHashes.count == 0 {
            throw PassiveAuthenticationError.UnableToParseSODHashes( "Unable to extract hashes" )
        }

        
        var errors : String = ""
        for (id,dgVal) in dataGroupsRead {
            guard let sodHashVal = sodHashes[id] else {
                // SOD and COM don't have hashes so these aren't errors
                if id != .SOD && id != .COM {
                    errors += "DataGroup \(id) is missing!\n"
                }
                continue
            }
            
            let computedHashVal = binToHexRep(dgVal.hash(sodHashAlgorythm))
            
            var match = true
            if computedHashVal != sodHashVal {
                errors += "\(id) invalid hash:\n  SOD hash:\(sodHashVal)\n   Computed hash:\(computedHashVal)\n"
                match = false
            }

            dataGroupHashes[id] = DataGroupHash(id: id.getName(), sodHash:sodHashVal, computedHash:computedHashVal, match:match)
        }
        
        if errors != "" {
            Logger.passportReader.error( "HASH ERRORS - \(errors)" )
            throw PassiveAuthenticationError.InvalidDataGroupHash(errors)
        }
        
        Logger.passportReader.debug( "Passport passed Datagroup Tampering check" )
        passportDataNotTampered = true
    }
    
    
    /**
     Read the LDSSecurityObject out of the SOD's signed content, as DER.

     fravash: THIS WALKED THE TEXT OF AN OPENSSL DUMP UNTIL 2026-09-14, keying
     off `d=2 OBJECT`, `d=3 INTEGER` and `d=3 OCTET STRING` and pulling values
     out of string ranges. A cross-implementation vector against
     `packages/eid/src/sod.ts` measured NINE divergences, and every one of them
     fell out of that mechanism rather than out of nine separate mistakes:

       - `currentDG` was cleared only inside the success branch, so an INTEGER
         that never found its OCTET STRING stayed set and the NEXT hash paired
         with it. That produced a table with ordinary looking numbers and one
         row carrying a hash the document declared under no number at all.
       - `[HEX DUMP]:` is absent when OpenSSL renders an OCTET STRING as
         printable text or when it is empty, and the row was silently skipped.
       - `Int(currentDG, radix: 16)` dropped rows whose number OpenSSL chose to
         render differently, which is how a data group SEVENTEEN written as
         `02 04 00 00 00 11` disappeared.
       - Nothing checked that a `DataGroupHash` was a SEQUENCE of an INTEGER
         then an OCTET STRING, so two INTEGERs and a hash invented rows.
       - Nothing refused a repeated data group number.

     And the `d=2`/`d=3` keys deserve their own line: depth is a property of the
     ENCODING NESTING, so a parser keyed on it reads a different table the day an
     encoder wraps one layer differently, with nothing going red.

     WHY THIS MATTERS MORE THAN A PARSER BEING UNTIDY. The per-site account
     number commits to the WHOLE signed table, so a row dropped, invented or
     mis-paired here is in that person's number permanently, and it is STABLE:
     the same document fails the same way on every read, so it never looks like
     a bug. Only a second implementation reading the same bytes reveals it.

     THE SHAPE, ICAO 9303 Part 10:

         LDSSecurityObject ::= SEQUENCE {
           version              INTEGER,
           hashAlgorithm        DigestAlgorithmIdentifier,
           dataGroupHashValues  SEQUENCE OF DataGroupHash,
           ldsVersionInfo       LDSVersionInfo OPTIONAL }
         DataGroupHash ::= SEQUENCE {
           dataGroupNumber      INTEGER,
           dataGroupHashValue   OCTET STRING }

     STRICT ON POSITION, LENIENT ON THE TAIL, and the asymmetry is deliberate.
     Position strictness is what makes mis-pairing structurally impossible.
     An element AFTER the OCTET STRING is ignored rather than refused, because
     the vector's `third-element-after-the-hash` case declares it accepted, it
     sits inside content the issuing state SIGNED so nobody can add one without
     breaking that signature, and we do not hold the normative text and so
     cannot tell whether the module carries an extension marker. If it does,
     refusing a trailing field would refuse every passport issued after the next
     revision.

     HEX IS UPPERCASE, WHICH IS NOT A STYLE CHOICE. `binToHexRep` uppercases,
     the tamper check compares against it as a string, and `sodDataGroupHashes`
     feeds the account number. Lowercasing here would fail every tamper check
     and change every account number ever issued.

     - Parameter signedData: the SOD's encapsulated content octets.
     - Returns: the digest algorithm name, the mapped table, and every row as
       the document declared it, in document order.
     */
    private func parseSODSignatureContent( _ signedData : Data ) throws -> (String, [DataGroupId : String], [SodDataGroupHash]){
        let bytes = [UInt8](signedData)

        /* The eContent IS the LDSSecurityObject, so there is exactly one
           top level element and it is a SEQUENCE. Checking the count rather
           than taking `first` refuses trailing rubbish after the structure. */
        guard let top = DER.children(in: bytes, from: 0, to: bytes.count),
              top.count == 1,
              top[0].tag == DER.sequence else {
            throw PassiveAuthenticationError.UnableToParseSODHashes( "The signed content is not a single DER SEQUENCE" )
        }
        guard let fields = DER.children(in: bytes, from: top[0].contentStart, to: top[0].contentEnd),
              fields.count >= 3 else {
            throw PassiveAuthenticationError.UnableToParseSODHashes( "The LDSSecurityObject is missing mandatory fields" )
        }
        guard fields[0].tag == DER.integer else {
            throw PassiveAuthenticationError.UnableToParseSODHashes( "The LDSSecurityObject has no version" )
        }

        /* THE ALGORITHM FROM THE FIELD THAT HOLDS IT, not from whichever dump
           line happened to contain the substring "sha256". The old reader keyed
           on `d=2 OBJECT`, which is a DEPTH, so any OID rendered at that depth
           could set it. */
        guard fields[1].tag == DER.sequence,
              let algorithmFields = DER.children(in: bytes, from: fields[1].contentStart, to: fields[1].contentEnd),
              let oid = algorithmFields.first,
              oid.tag == DER.objectIdentifier,
              let sodHashAlgo = NFCPassportModel.digestName(
                  for: Array(bytes[oid.contentStart..<oid.contentEnd]) ) else {
            throw PassiveAuthenticationError.UnableToParseSODHashes( "Unable to find hash algorythm used" )
        }

        guard fields[2].tag == DER.sequence,
              let tableRows = DER.children(in: bytes, from: fields[2].contentStart, to: fields[2].contentEnd) else {
            throw PassiveAuthenticationError.UnableToParseSODHashes( "The data group hash table is not a SEQUENCE" )
        }

        var sodHashes : [DataGroupId : String] = [:]
        /* fravash: every row as the SOD carries it, keeping the raw number that
           `sodHashes` cannot represent. Appended in document order. */
        var sodRows : [SodDataGroupHash] = []
        var seen = Set<Int>()

        let dgList : [DataGroupId] = [.COM,.DG1,.DG2,.DG3,.DG4,.DG5,.DG6,.DG7,.DG8,.DG9,.DG10,.DG11,.DG12,.DG13,.DG14,.DG15,.DG16,.SOD]

        for row in tableRows {
            guard row.tag == DER.sequence,
                  let parts = DER.children(in: bytes, from: row.contentStart, to: row.contentEnd),
                  parts.count >= 2,
                  parts[0].tag == DER.integer,
                  parts[1].tag == DER.octetString else {
                throw PassiveAuthenticationError.UnableToParseSODHashes( "A DataGroupHash is not an INTEGER followed by an OCTET STRING" )
            }
            guard let id = DER.integerValue(bytes, from: parts[0].contentStart, to: parts[0].contentEnd) else {
                throw PassiveAuthenticationError.UnableToParseSODHashes( "A DataGroupHash has a dataGroupNumber this reader cannot represent" )
            }
            /* A repeated number lets a forger offer two candidate hashes for one
               group and have a lenient verifier match either. Refuse. */
            guard seen.insert(id).inserted else {
                throw PassiveAuthenticationError.UnableToParseSODHashes( "Data group \(id) appears more than once in the hash table" )
            }

            /* THE BYTES, so neither printable content nor a zero length can make
               a row disappear the way `[HEX DUMP]:` did. */
            let hash = binToHexRep( Array(bytes[parts[1].contentStart..<parts[1].contentEnd]) )

            sodRows.append( SodDataGroupHash( dataGroupNumber: id, hash: hash ) )

            /* AND ONLY THEN THE MAPPED ONE, IF IT MAPS. `id` comes straight out
               of the document and is unbounded; `dgList` has 18 entries. An
               unmappable number is skipped rather than dropped: it is already in
               `sodRows` above. */
            if id >= 0 && id < dgList.count {
                sodHashes[dgList[id]] = hash
            }
        }

        Logger.passportReader.debug( "Parse SOD - Using Algo - \(sodHashAlgo)" )

        return (sodHashAlgo, sodHashes, sodRows)
    }

    /**
     Map a digest OID's content bytes to the name the rest of this file uses.

     BY BYTES RATHER THAN BY A RENDERED STRING. The old reader looked for the
     substring "sha256" in a dump line, which is a text match against something
     OpenSSL chose to print.
     */
    private static func digestName( for oidBytes : [UInt8] ) -> String? {
        switch oidBytes {
        case [0x2B, 0x0E, 0x03, 0x02, 0x1A]:                               return "SHA1"
        case [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04]:       return "SHA224"
        case [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]:       return "SHA256"
        case [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]:       return "SHA384"
        case [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]:       return "SHA512"
        default:                                                            return nil
        }
    }
}

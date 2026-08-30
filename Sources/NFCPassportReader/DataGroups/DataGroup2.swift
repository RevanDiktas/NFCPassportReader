//
//  DataGroup2.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

#if !os(macOS)
import UIKit
#endif

@available(iOS 13, macOS 10.15, *)
public class DataGroup2 : DataGroup {
    private enum FaceImageFormat {
        case jpeg
        case jp2
        case jpeg2000Codestream
    }
    
    
    public private(set) var nrImages : Int = 0
    public private(set) var versionNumber : Int = 0
    public private(set) var lengthOfRecord : Int = 0
    public private(set) var numberOfFacialImages : Int = 0
    public private(set) var facialRecordDataLength : Int = 0
    public private(set) var nrFeaturePoints : Int = 0
    public private(set) var gender : Int = 0
    public private(set) var eyeColor : Int = 0
    public private(set) var hairColor : Int = 0
    public private(set) var featureMask : Int = 0
    public private(set) var expression : Int = 0
    public private(set) var poseAngle : Int = 0
    public private(set) var poseAngleUncertainty : Int = 0
    public private(set) var faceImageType : Int = 0
    public private(set) var imageDataType : Int = 0
    public private(set) var imageWidth : Int = 0
    public private(set) var imageHeight : Int = 0
    public private(set) var imageColorSpace : Int = 0
    public private(set) var sourceType : Int = 0
    public private(set) var deviceType : Int = 0
    public private(set) var quality : Int = 0
    public private(set) var imageData : [UInt8] = []
    
    public override var datagroupType: DataGroupId { .DG2 }
    
#if !os(macOS)
    func getImage() -> UIImage? {
        if imageData.count == 0 {
            return nil
        }
        
        let image = UIImage(data:Data(imageData) )
        return image
    }
#endif
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        
        var tag = try getNextTag()
        try verifyTag(tag, equals: 0x7F61)
        _ = try getNextLength()
        
        // Tag should be 0x02
        tag = try getNextTag()
        try verifyTag(tag, equals: 0x02)
        nrImages = try Int(getNextValue()[0])
        
        // Next tag is 0x7F60
        tag = try getNextTag()
        try verifyTag(tag, equals: 0x7F60)
        _ = try getNextLength()
        
        // Next tag is 0xA1 (Biometric Header Template) - don't care about this
        tag = try getNextTag()
        try verifyTag(tag, equals: 0xA1)
        _ = try getNextValue()
        
        // Now we get to the good stuff - next tag is either 5F2E or 7F2E
        tag = try getNextTag()
        try verifyTag(tag, oneOf: [0x5F2E, 0x7F2E])
        let value = try getNextValue()

        /* fravash: TWO ENCODINGS LIVE BEHIND THIS TAG NOW, AND THE OUTER FRAMING
           DOES NOT DISTINGUISH THEM.

           ICAO is migrating DG2 from ISO/IEC 19794-5 to ISO/IEC 39794-5.
           Inspection systems have had to read both since 1 February 2026, issuing
           States may use either until 1 January 2030, and everything ABOVE this
           point is byte-identical between them. Only the content differs: a
           19794-5 facial record begins with the four bytes 'F' 'A' 'C' 0x00,
           where a 39794-5 one is ASN.1 DER and begins with a context tag.

           Before this branch existed, a 39794-5 document threw UnknownImageFormat
           here, and because the caller read every data group in one unguarded
           loop that cost the ENTIRE read, not just the portrait.

           The discriminator is the record header rather than a length or a guess,
           because it is the one thing the two encodings cannot share. */
        if value.count >= 4,
           value[0] == 0x46, value[1] == 0x41, value[2] == 0x43, value[3] == 0x00 {
            try parseISO19794_5( data:value )
        } else {
            try parseISO39794_5( data:value )
        }
    }

    /**
     fravash: pull the portrait out of an ISO/IEC 39794-5 encoded DG2.

     THIS EXTRACTS THE IMAGE AND DELIBERATELY NOTHING ELSE. 39794-5 is a large
     schema carrying landmarks, quality blocks, capture device details and
     anthropometric metadata, none of which anything downstream reads. Writing a
     full schema parser would be weeks of work whose output we would discard, and
     every field parsed is another place to be wrong about attacker influenced
     input. So this walks one known path to `representationData2D` and stops.

     THE PATH, from the content of the 5F2E/7F2E tag:

         [1]  ->  [APPLICATION 5]  ->  [1]  ->  SEQUENCE  ->  [1]  ->  [0]  ->  [0]  ->  [0]
                  FaceImageDataBlock   repre-   Represen-   image-   base  2DBlock  representation
                                       sentat-  tationBlock Repre-                  Data2D
                                       ionBlocks            sentation

     IT SEARCHES SIBLINGS RATHER THAN COUNTING THEM. Most members at these levels
     are OPTIONAL, so position is not stable: the two official ICAO vectors differ
     in exactly this way, one carrying only mandatory fields and one carrying all
     of them. Searching by tag parses both; counting would parse one.

     VERIFIED AGAINST THE OFFICIAL VECTORS, not against my reading of the spec.
     github.com/ICAO-TRIP-ISO-WG3/39794-5-AP publishes two reference DG2 files;
     both yield the same 15000 byte JP2 portrait, which decodes at 413x531.

     WHAT IS NOT POPULATED, stated so nobody reads a zero as a measurement.
     `imageWidth`, `imageHeight` and every other ISO 19794-5 header field stay at
     their defaults on this path. They are not present in the same form here, and
     the authoritative dimensions are the decoded image's own. A caller that needs
     them should decode and ask the image.
     */
    func parseISO39794_5( data : [UInt8] ) throws {
        guard let root = DER.find(tag: 0x65, in: data, from: 0, to: data.count),
              let representations = DER.find(tag: 0xA1, in: data, from: root.contentStart, to: root.contentEnd),
              let block = DER.find(tag: 0x30, in: data, from: representations.contentStart, to: representations.contentEnd),
              let representation = DER.find(tag: 0xA1, in: data, from: block.contentStart, to: block.contentEnd),
              /* Two CHOICE wrappers: ImageRepresentation.base, then
                 ImageRepresentationBase.imageRepresentation2DBlock. Both are [0].
                 An extensionBlock ([1]) is a future encoding we do not implement,
                 and failing here is the honest outcome for it. */
              let base = DER.find(tag: 0xA0, in: data, from: representation.contentStart, to: representation.contentEnd),
              let twoD = DER.find(tag: 0xA0, in: data, from: base.contentStart, to: base.contentEnd),
              let payload = DER.find(tag: 0x80, in: data, from: twoD.contentStart, to: twoD.contentEnd)
        else {
            throw NFCPassportReaderError.UnknownImageFormat
        }

        let bytes = Array(data[payload.contentStart..<payload.contentEnd])
        /* THE SAME CONTAINER CHECK THE OTHER PATH USES. 39794-5 changed how the
           portrait is WRAPPED, not what it is: the payload is still JPEG or
           JPEG 2000, so an unrecognised one is still UnknownImageFormat rather
           than something we hand onward and hope about. */
        guard bytes.starts(with: [0xff, 0xd8, 0xff])
                || bytes.starts(with: [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20])
                || bytes.starts(with: [0xff, 0x4f, 0xff, 0x51])
        else {
            throw NFCPassportReaderError.UnknownImageFormat
        }
        imageData = bytes
    }
    
    func parseISO19794_5( data : [UInt8] ) throws {
        // Validate header - 'F', 'A' 'C' 0x00 - 0x46414300
        if data[0] != 0x46 && data[1] != 0x41 && data[2] != 0x43 && data[3] != 0x00 {
            throw NFCPassportReaderError.InvalidResponse(
                dataGroupId: datagroupType,
                expectedTag: 0x46,
                actualTag: Int(data[0])
            )
        }
        
        var offset = 4
        versionNumber = binToInt(data[offset..<offset+4])
        offset += 4
        lengthOfRecord = binToInt(data[offset..<offset+4])
        offset += 4
        numberOfFacialImages = binToInt(data[offset..<offset+2])
        offset += 2
        
        facialRecordDataLength = binToInt(data[offset..<offset+4])
        offset += 4

        nrFeaturePoints = binToInt(data[offset..<offset+2])
        offset += 2
        gender = binToInt(data[offset..<offset+1])
        offset += 1
        eyeColor = binToInt(data[offset..<offset+1])
        offset += 1
        hairColor = binToInt(data[offset..<offset+1])
        offset += 1
        featureMask = binToInt(data[offset..<offset+3])
        offset += 3
        expression = binToInt(data[offset..<offset+2])
        offset += 2
        poseAngle = binToInt(data[offset..<offset+3])
        offset += 3
        poseAngleUncertainty = binToInt(data[offset..<offset+3])
        offset += 3
        
        // Features (not handled). There shouldn't be any but if for some reason there were,
        // then we are going to skip over them
        // The Feature block is 8 bytes
        offset += nrFeaturePoints * 8
        
        faceImageType = binToInt(data[offset..<offset+1])
        offset += 1
        imageDataType = binToInt(data[offset..<offset+1])
        offset += 1
        imageWidth = binToInt(data[offset..<offset+2])
        offset += 2
        imageHeight = binToInt(data[offset..<offset+2])
        offset += 2
        imageColorSpace = binToInt(data[offset..<offset+1])
        offset += 1
        sourceType = binToInt(data[offset..<offset+1])
        offset += 1
        deviceType = binToInt(data[offset..<offset+2])
        offset += 2
        quality = binToInt(data[offset..<offset+2])
        offset += 2
        
        
        // Make sure that the image data at least has a valid header
        // Either JPG or JPEG2000
        
        
        imageData = try extractFaceImageData(
            from: data,
            offset: offset
        )
    }
    
    private func extractFaceImageData(from data: [UInt8], offset: Int) throws -> [UInt8] {
        let jpegHeader : [UInt8] = [0xff,0xd8,0xff,0xe0,0x00,0x10,0x4a,0x46,0x49,0x46]
        let jpeg2000BitmapHeader : [UInt8] = [0x00,0x00,0x00,0x0c,0x6a,0x50,0x20,0x20,0x0d,0x0a]
        let jpeg2000CodestreamBitmapHeader : [UInt8] = [0xff,0x4f,0xff,0x51]
        
        let remaining = Array(data[offset...])
        
        // Check for JPEG Image
        if remaining.starts(with: jpegHeader) {
            guard let end = findJPEGEnd(in: remaining) else {
                throw NFCPassportReaderError.UnknownImageFormat
            }
            return Array(remaining[..<end])
        }
        
        // Check for jpeg2000CodestreamBitmapHeader
        if remaining.starts(with: jpeg2000CodestreamBitmapHeader) {
            guard let end = findJPEG2000CodestreamEnd(in: remaining) else {
                throw NFCPassportReaderError.UnknownImageFormat
            }
            return Array(remaining[..<end])
        }
        
        // Check for JPEG2000Bitmap
        if remaining.starts(with: jpeg2000BitmapHeader) {
            let maxEnd = data.count
            return try extractJP2BoxData(from: data, offset: offset, maxEnd: maxEnd)
        }
        
        throw NFCPassportReaderError.UnknownImageFormat
    }
    
    private func extractJP2BoxData(from data: [UInt8], offset: Int, maxEnd: Int) throws -> [UInt8] {
        var p = offset
        
        while p + 8 <= maxEnd {
            let boxStart = p
            let length = binToInt(data[p..<p + 4])
            p += 4
            
            let boxType = Array(data[p..<p + 4])
            p += 4
            
            let boxEnd: Int
            
            if length == 0 {
                // Box extends to end of containing data
                boxEnd = maxEnd
            } else if length == 1 {
                // XLBox: 64-bit box length
                guard p + 8 <= maxEnd else {
                    throw NFCPassportReaderError.UnknownImageFormat
                }
                
                let largeLength = binToInt64(data[p..<p + 8])
                p += 8
                
                guard largeLength >= 16 else {
                    throw NFCPassportReaderError.UnknownImageFormat
                }
                
                boxEnd = boxStart + Int(largeLength)
            } else {
                guard length >= 8 else {
                    throw NFCPassportReaderError.UnknownImageFormat
                }
                
                boxEnd = boxStart + length
            }
            
            guard boxEnd <= maxEnd else {
                throw NFCPassportReaderError.UnknownImageFormat
            }
            
            p = boxEnd
            
            // jp2c box: this is the codestream box.
            // Once we have consumed it, the JP2 image is complete.
            if boxType == [0x6A, 0x70, 0x32, 0x63] {
                return Array(data[offset..<boxEnd])
            }
        }
        
        throw NFCPassportReaderError.UnknownImageFormat
    }
    
    private func findJPEGEnd(in data: [UInt8]) -> Int? {
        guard data.count >= 2 else { return nil }
        
        // Go backwards to find end of file marker
        
        for i in stride(from: data.count - 2, through: 0, by: -1) {
            if data[i] == 0xFF && data[i + 1] == 0xD9 {
                return i + 2
            }
        }
        
        return nil
    }
    
    private func findJPEG2000CodestreamEnd(in data: [UInt8]) -> Int? {
        // JPEG2000 codestream EOC marker
        return findJPEGEnd(in: data)
    }
    
    private func binToInt64(_ slice: ArraySlice<UInt8>) -> UInt64 {
        var value: UInt64 = 0
        
        for byte in slice {
            value = (value << 8) | UInt64(byte)
        }
        
        return value
    }
}

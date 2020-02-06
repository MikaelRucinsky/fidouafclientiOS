import Foundation
import Security
import UIKit

class Utils {

    static func isFacetIdValid(trustedFacetList: [TrustedFacets], version: Version, appFacetId: String) -> Bool {
        for trustedFacets in trustedFacetList {
            if (trustedFacets.version.minor <= version.minor && trustedFacets.version.major <= version.major) {

                let searchHelper: [String] = appFacetId.components(separatedBy: ",")
                for facetId in searchHelper {
                    for id in trustedFacets.ids {
                        if (id == facetId) {
                            return true
                        }
                    }
                }
            }
        }
        return false
    }

    static func getFacetId(sourceApplication: String?) -> String {
        if sourceApplication != nil {
            return "ios:bundle-id:\(sourceApplication!)"
        } else {
            return "ios:bundle-id:\(Bundle.main.bundleIdentifier!)"
        }
    }
    
    static func generateKeyID(appID: String) -> String? {
        var bytes = Data(count: 32)
        let result = bytes.withUnsafeMutableBytes{ SecRandomCopyBytes(kSecRandomDefault, 30, $0) }

        if result == errSecSuccess {
            if let appIdData = appID.data(using: .utf8) {
                return Hash.sha256(data: appIdData + bytes).base64UrlWithoutPaddingEncodedString(removeBackslash: false)
            } else {
                return nil
            }
            
//            return bytes.base64EncodedString()
//                    .replacingOccurrences(of: "/", with: "")
//                    .replacingOccurrences(of: "+", with: "")
//                    .replacingOccurrences(of: "=", with: "")
        }
        return nil
    }

    static func getRandomBytes(length: Int) -> Data? {
        var bytes = Data(count: length)
        let result = bytes.withUnsafeMutableBytes{ SecRandomCopyBytes(kSecRandomDefault, length, $0) }

        if result == errSecSuccess {
            return bytes
        }
        return nil
    }
    
    static func generateAccessControlCreateFlags() -> SecAccessControlCreateFlags {
        var flags: SecAccessControlCreateFlags = [.userPresence, .privateKeyUsage]
        if (UIDevice.current.modelName.starts(with: "iPhone5")) {
            flags = [.userPresence]
        }
        return flags
    }
    
    static func generatePrivateLabel(appId: String, keyId: String) -> String {
        let hash = Hash.sha256(data: appId.data(using: .utf8)! + keyId.data(using: .utf8)!).base64UrlWithoutPaddingEncodedString(removeBackslash: false)
        return "\(hash)-private"
    }
    
    static func generatePublicLabel(appId: String, keyId: String) -> String {
        let hash = Hash.sha256(data: appId.data(using: .utf8)! + keyId.data(using: .utf8)!).base64UrlWithoutPaddingEncodedString(removeBackslash: false)
        return "\(hash)-public"
    }
    
    static func validatePolicy(policy: Policy) -> Bool {
        guard !policy.accepted.isEmpty else { return false }
        let acceptedMcValidationresult = policy.accepted.flatMap { $0.map { mc in mc.isValid() } }
        guard !acceptedMcValidationresult.contains(false) else { return false }
        
        let disallowedMcValidationResult = policy.disallowed?.map { $0.isValid() } ?? []
        guard !disallowedMcValidationResult.contains(false) else { return false }
        
        return true
    }
    
    static func getTrustedFacetList(appId: String, completionHandler: @escaping (TrustedFacetList?, FidoError) -> Void) {
        if (appId.starts(with: "https")) {
            HttpService.getTrustedFacetsFromServer(appId) { trustedFacetList in
                guard let list = trustedFacetList else {
                    completionHandler(nil, .UNTRUSTED_FACET_ID)
                    return
                }
                completionHandler(list, .NO_ERROR)
                return
            }
        } else {
            completionHandler(nil, .NO_ERROR)
            return
        }
    }
    
    static func checkTrustedFacetList(trustedFacetList: TrustedFacetList, sourceApplication: String) -> Bool {
        let list = trustedFacetList.trustedFacets.filter { $0.version.major == 1 && $0.version.minor == 0 }
        guard list.count == 1 else { return false }
        
        return list[0].ids.contains("ios:bundle-id:\(sourceApplication)")
    }
    
    static func isBase64UrlEncoded(_ string: String) -> Bool {
        do {
            let regex = try NSRegularExpression(pattern: "[a-zA-z0-9-_]+")
            let matches = regex.matches(in: string, range: NSRange(string.startIndex..., in: string))
            guard matches.count == 1 else { return false }
            
            let regexCount = matches.map{ $0.range.length }.reduce(0) { count, strCount in return count + strCount }
            guard regexCount == string.count else { return false }
            
            let base64String = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            let remainder = base64String.count % 4
            let base64StringWithPadding = base64String.padding(toLength: base64String.count + (4 - remainder) % 4, withPad: "=", startingAt: 0)
            
            guard let _ = Data(base64Encoded: base64StringWithPadding) else { return false }
            
            return true
        } catch _ {
            return false
        }
    }
    
    static func isValidAAID(_ aaid: String) -> Bool {
        do {
            let regex = try NSRegularExpression(pattern: "^[0-9A-Fa-f]{4}#[0-9A-Fa-f]{4}$")
            let matches = regex.matches(in: aaid, range: NSRange(aaid.startIndex..., in: aaid))
            guard matches.count == 1 else { return false }
            
            let regexCount = matches.map { $0.range.length }.reduce(0) { count, strCount in return count + strCount }
            guard regexCount == aaid.count else { return false }
            
            return true
        } catch {
            return false
        }
    }
    
    // encrypt response with given key
    static func encryptResponse(plaintext: Data, secretKey: Data) -> XCallbackUrlJweResponse? {
        // validate secret key
        guard secretKey.count == 32 else {
            print("SecretKey not validated: \(secretKey.count)")
            return nil
        }
        // generate random iv
        guard let iv = Utils.getRandomBytes(length: 16) else {
            print("iv not generated")
            return nil
        }
        
        let macKey = secretKey[0..<16]
        let encKey = secretKey[16..<secretKey.count]
        
        // encrypt plaintext
        var encryptedByteCount: Int = 0
        var ciphertext = [UInt8](repeating: 0, count: iv.count + plaintext.count + kCCBlockSizeAES128)
        
        let status = encKey.withUnsafeBytes { encKeyBytes in
            iv.withUnsafeBytes { ivBytes in
                plaintext.withUnsafeBytes { plaintextBytes in
                    return CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        encKeyBytes.baseAddress,
                        kCCKeySizeAES128,
                        ivBytes.baseAddress,
                        plaintextBytes.baseAddress,
                        plaintext.count,
                        &ciphertext,
                        ciphertext.count,
                        &encryptedByteCount
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            print("CCCryptStatus: \(status)")
            return nil }
        
        let ciphertextData = Data(bytes: UnsafePointer<UInt8>(ciphertext), count: encryptedByteCount)
        
        // compute AL (there is no AAD, so AL is a 64-bit string of zeros - normally it would be the number of bits of AAD expressed as big-endian)
        let al: [UInt8] = [ 0, 0, 0, 0, 0, 0, 0, 0 ]
        let alData = Data(bytes: al)
        
        // compute HMAC-SHA256 over IV + ciphertext + AL
        let hmacData = NSMutableData()
        hmacData.append(iv)
        hmacData.append(ciphertextData)
        hmacData.append(alData)
        
        let mac = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA256_DIGEST_LENGTH))
        macKey.withUnsafeBytes { macKeyBytes in
            (hmacData as Data).withUnsafeBytes { hmacDataBytes in
                CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA256),
                    macKeyBytes,
                    macKey.count,
                    hmacDataBytes.baseAddress,
                    hmacData.count,
                    mac
                )
            }
        }
        
        let macData = Data(bytes: mac, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        // truncate the mac (first 16 bytes only) to become the tag
        let tagData: Data = macData[0..<16]
        
        return XCallbackUrlJweResponse(
            unprotected: XCallbackUrlJweHeader(alg: "dir", enc: "A128CBC-HS256"),
            iv: iv.base64UrlWithoutPaddingEncodedString(removeBackslash: false),
            ciphertext: ciphertextData.base64UrlWithoutPaddingEncodedString(removeBackslash: false),
            tag: tagData.base64UrlWithoutPaddingEncodedString(removeBackslash: false)
        )
    }
    
}

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
        var bytes = Data(count: 30)
        let result = bytes.withUnsafeMutableBytes{ SecRandomCopyBytes(kSecRandomDefault, 30, $0) }

        if result == errSecSuccess {
            return bytes.base64EncodedString()
                    .replacingOccurrences(of: "/", with: "")
                    .replacingOccurrences(of: "+", with: "")
                    .replacingOccurrences(of: "=", with: "")
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
        return "\(appId)-\(keyId)-private"
    }
    
    static func generatePublicLabel(appId: String, keyId: String) -> String {
        return "\(appId)-\(keyId)-public"
    }
    
    static func getTrustedFacetList(urlString: String, count: Int = 0, completion: @escaping ([TrustedFacets]?) -> Void) throws {
//        guard let url = URL(string: urlString) else { throw InternalError.Default("Not an URL") }
//        DispatchQueue.global().async {
//            URLSession.shared.dataTask(with: url) { dataOption, response, error in
//                if let httpResponse = (response as? HTTPURLResponse), let data = dataOption {
//                    if (httpResponse.statusCode == 200) {
//                        DispatchQueue.main.async {
//                            completion(TrustedFacets.getArrayFromData(data: data))
//                        }
//                    } else if ((300...399).contains(httpResponse.statusCode)) {
//                        let httpAuthorize = httpResponse.allHeaderFields["FIDO-AppID-Redirect-Authorized"]
//                        let location = httpResponse.allHeaderFields["Location"] as? String
//                        if ((httpAuthorize as? Bool) == true && location != nil) {
//                            try getTrustedFacetList(urlString: location, count: count + 1, completion: completion)
//                        }
//                    } else {
//                        completion(nil)
//                    }
//                }
//            }
//        }
//        throw InternalError.Default("Failure getting TrustedFacetList from '\(urlString)'")
    }
    
    static func validatePolicy(policy: Policy) -> Bool {
        guard !policy.accepted.isEmpty else { return false }
        let acceptedMcValidationresult = policy.accepted.flatMap { $0.map { mc in mc.isValid() } }
        guard !acceptedMcValidationresult.contains(false) else { return false }
        
        let disallowedMcValidationResult = policy.disallowed?.map { $0.isValid() } ?? []
        guard !disallowedMcValidationResult.contains(false) else { return false }
        
        return true
    }
    
    static func isBase64UrlEncoded(_ string: String) -> Bool {
        do {
            let regex = try NSRegularExpression(pattern: "[a-zA-z0-9-_]*")
            let matches = regex.matches(in: string, range: NSRange(string.startIndex..., in: string))
            print("numberOfMatches: \(regex.numberOfMatches(in: string, range: NSRange(string.startIndex..., in: string)))")
            print("matches.count: \(matches.count)")
            print("matches: \(matches)")
            
            let base64String = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            let remainder = base64String.count % 4
            let base64StringWithPadding = base64String.padding(toLength: base64String.count + (4 - remainder) % 4, withPad: "=", startingAt: 0)
            
            guard let _ = Data(base64Encoded: base64StringWithPadding) else { return false }
            
            return true
        } catch _ {
            return false
        }
    }
    
}

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

    static func getFacetId() -> String {
        return "ios:bundle-id:\(Bundle.main.bundleIdentifier!)"
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
}

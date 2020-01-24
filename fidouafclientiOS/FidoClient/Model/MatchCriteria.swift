import Foundation

struct MatchCriteria: Codable {

    let aaid: [String]?
    let vendorID: [String]?
    let keyIDs: [String]?
    let userVerification: Int?
    let keyProtection: Int?
    let matcherProtection: Int?
    let attachmentHint: Int?
    let tcDisplay: Int?
    let authenticationAlgorithms: [Int]?
    let assertionSchemes: [String]?
    let attestationTypes: [Int]?
    let authenticatorVersion: Int?
    let exts: [Extension]?
}

extension MatchCriteria {
    func isValid() -> Bool {
        if (exts != nil && exts!.filter { $0.id.count > 32 || $0.id.count <= 0 }.count > 0 ) {
            return false
        }
        
        if (aaid == nil) {
            if (authenticationAlgorithms == nil || assertionSchemes == nil) {
                return false
            }
        }
        
        if (aaid != nil) {
            if (
                vendorID != nil ||
                userVerification != nil ||
                keyProtection != nil ||
                matcherProtection != nil ||
                tcDisplay != nil ||
                authenticationAlgorithms != nil ||
                assertionSchemes != nil ||
                attestationTypes != nil
                ) {
                return false
            }
        }
        
        if (keyIDs != nil) {
            if (keyIDs!.map { Utils.isBase64UrlEncoded($0) }.contains(false) ) {
                return false
            }
        }
        
        let failIfUnknownExtensions = exts?.filter { $0.fail_if_unknown } ?? []
        let unknownExtensions = failIfUnknownExtensions.filter { AuthenticatorMetadata.authenticator.supportedExtensionIDs.contains($0.id) }
        guard unknownExtensions.isEmpty else { return false }
        
        // find extensionIds which are longer than 32 characters
        let longOrShortExtIds = exts?.filter { $0.id.count > 32 || $0.id.count <= 0 } ?? []
        guard longOrShortExtIds.isEmpty else { return false }
        
        return true
    }
}

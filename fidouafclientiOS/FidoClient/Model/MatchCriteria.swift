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
    
    func matchesAuthenticator(authenticator: Authenticator) -> Bool {
        if ((aaid != nil && aaid!.count != 1) || (aaid != nil && aaid![0] != authenticator.aaid)) {
            return false
        }
        
        if ((vendorID != nil && vendorID!.count != 1) || (vendorID != nil && vendorID![0] != authenticator.aaid.split(separator: "#")[0])) {
            return false
        }
        
        if (userVerification != nil && userVerification! != authenticator.userVerification) {
            return false
        }
        
        if (keyProtection != nil && keyProtection! != authenticator.keyProtection) {
            return false
        }
        
        if (matcherProtection != nil && matcherProtection! != authenticator.matcherProtection) {
            return false
        }
        
        if (attachmentHint != nil && attachmentHint! != authenticator.attachmentHint) {
            return false
        }
        
        if (tcDisplay != nil && !(tcDisplay! != 0x01 || tcDisplay! != 0x02 || tcDisplay! != 0x03)) {
            return false
        }
        
        if ((authenticationAlgorithms != nil && authenticationAlgorithms!.count != 1) || (authenticationAlgorithms != nil && authenticationAlgorithms![0] != authenticator.authenticationAlgorithm)) {
            return false
        }
        
        if ((assertionSchemes != nil && assertionSchemes!.count != 1) || (assertionSchemes != nil && assertionSchemes![0] != authenticator.assertionScheme)) {
            return false
        }
        
        if ((attestationTypes != nil && attestationTypes!.count != 1) || (attestationTypes != nil && attestationTypes![0] != authenticator.attestationTypes[0])) {
            return false
        }
        
        return true
    }
    
    private func isKeyIdRegisteredForAuthenticator(appId: String, keyIds: [String]) -> Bool {
        guard keyIds.count > 0 else { return false }
        
        guard let storedKeys = Storage.load(appId: appId) else { return false }
        let filtered = storedKeys.values.filter { keyIds.contains($0) }
        return filtered.count > 0
    }
}

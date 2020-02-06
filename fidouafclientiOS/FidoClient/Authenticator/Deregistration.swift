import Foundation

class Deregistration {
    
    func process(deregRequest: DeregistrationRequest, appId: String) {

        deregRequest.authenticators.forEach { deregisterAuthenticator in
            do {
                // TODO: delete key from Storage and delete all if no keyID is spefified
                if (Storage.hasKeyId(appId: appId, keyId: deregisterAuthenticator.keyID) && deregisterAuthenticator.aaid == AuthenticatorMetadata.authenticator.aaid) {
                    try deleteKey(appId: appId, keyId: deregisterAuthenticator.keyID)
                } else {
                    let keyIds = Storage.load(appId: appId) ?? [:]
                    try Array(keyIds.values).forEach { keyId in
                        try deleteKey(appId: appId, keyId: keyId)
                    }
                }
            } catch let error {
                debugPrint("Failure while deleting KeyPair with ID: \(deregisterAuthenticator.keyID): \(error)")
            }
        }
    }
    
    private func deleteKey(appId: String, keyId: String) throws {
        let ecHelper = EllipticCurveKeyPair.Helper(
                publicLabel: Utils.generatePublicLabel(appId: appId, keyId: keyId),
                privateLabel: Utils.generatePrivateLabel(appId: appId, keyId: keyId),
                operationPrompt: "",
                sha256: Hash.sha256,
                accessControl: try! EllipticCurveKeyPair.Helper.createAccessControl(protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags: Utils.generateAccessControlCreateFlags()))
        let ecManager = EllipticCurveKeyPair.Manager(helper: ecHelper)
        try ecManager.deleteKeyPair()
        
        let storedUserAndKeys = Storage.load(appId: appId) ?? [:]
        let filtered = storedUserAndKeys.filter { key, value in value != keyId }
        Storage.store(appId: appId, dict: filtered)
    }
    
}

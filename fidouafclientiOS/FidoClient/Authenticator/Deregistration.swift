import Foundation

class Deregistration {
    
    func process(deregRequest: DeregistrationRequest, appId: String) {

        deregRequest.authenticators.forEach { deregisterAuthenticator in
            do {
                if (Storage.hasKeyId(appId: appId, keyId: deregisterAuthenticator.keyID) && deregisterAuthenticator.aaid == AuthenticatorMetadata.authenticator.aaid) {
                    let ecHelper = EllipticCurveKeyPair.Helper(
                            publicLabel: Utils.generatePublicLabel(appId: appId, keyId: deregisterAuthenticator.keyID),
                            privateLabel: Utils.generatePrivateLabel(appId: appId, keyId: deregisterAuthenticator.keyID),
                            operationPrompt: "",
                            sha256: Hash.sha256,
                            accessControl: try! EllipticCurveKeyPair.Helper.createAccessControl(protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags: Utils.generateAccessControlCreateFlags()))
                    let ecManager = EllipticCurveKeyPair.Manager(helper: ecHelper)
                    try ecManager.deleteKeyPair()
                }
            } catch let error {
                debugPrint("Failure while deleting KeyPair with ID: \(deregisterAuthenticator.keyID): \(error)")
            }
        }
    }
}

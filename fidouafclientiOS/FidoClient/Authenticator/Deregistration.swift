import Foundation

class Deregistration {
    
    func process(deregRequest: DeregistrationRequest) {

        deregRequest.authenticators.forEach { deregisterAuthenticator in
            do {
                if (Storage.hasKeyId(appId: deregRequest.header.appID, keyId: deregisterAuthenticator.keyID) && deregisterAuthenticator.aaid == "A4A4#0002") {
                    let ecHelper = EllipticCurveKeyPair.Helper(
                            publicLabel: Utils.generatePublicLabel(appId: deregRequest.header.appID, keyId: deregisterAuthenticator.keyID),
                            privateLabel: Utils.generatePrivateLabel(appId: deregRequest.header.appID, keyId: deregisterAuthenticator.keyID),
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

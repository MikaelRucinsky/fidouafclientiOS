import Foundation
import Security

class Registration {

    var ecManager: EllipticCurveKeyPair.Manager!

    init() {}

    func process(regRequest: RegistrationRequest, finalChallenge: String) -> AuthenticatorRegistrationAssertion? {
        do {
            
            let keyId = Utils.generateKeyID(appID: regRequest.header.appID)!
            let internKeyId = keyId.data(using: .utf8)!.base64UrlWithoutPaddingEncodedString(removeBackslash: false)
            let ecHelper = EllipticCurveKeyPair.Helper(
                    publicLabel: Utils.generatePublicLabel(appId: regRequest.header.appID, keyId: internKeyId),
                    privateLabel: Utils.generatePrivateLabel(appId: regRequest.header.appID, keyId: internKeyId),
                    operationPrompt: getOperationPrompt(),
                    sha256: Hash.sha256,
                    accessControl: try! EllipticCurveKeyPair.Helper.createAccessControl(protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags: Utils.generateAccessControlCreateFlags()))
            self.ecManager = EllipticCurveKeyPair.Manager(helper: ecHelper)
            let _ = try self.ecManager.generate()

            var assertion = Data()
            assertion.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_UAFV1_REG_ASSERTION.rawValue))
            let uafV1Krd = try getUafV1Krd(keyId: keyId, finalChallenge: finalChallenge)
            let attestationTag = try getAttestationTag(signedData: uafV1Krd)

            assertion.append(contentsOf: UnsignedUtil.encodeInt(int: uafV1Krd.count + attestationTag.count))
            assertion.append(contentsOf: uafV1Krd)
            assertion.append(contentsOf: attestationTag)

            Storage.storeKeyId(appId: regRequest.header.appID, keyId: internKeyId)

            return AuthenticatorRegistrationAssertion(
                    assertionScheme: "UAFV1TLV",
                    assertion: assertion.base64UrlWithoutPaddingEncodedString(removeBackslash: false),
                    tcDisplayPNGCharacteristics: [],
                    exts: [])
        } catch let error {
            debugPrint("Failure while generating Authenticator Registration response: \(error)")
        }
        return nil
    }
    
    private func getOperationPrompt() -> String {
        var operationPrompt = ""
        // used if carthage
        if let bundle = Bundle(identifier: "io.hanko.FidoUafClientiOS") {
            operationPrompt = NSLocalizedString("biomentryOperationPromptReg", tableName: "fidouafclient", bundle: bundle, value: "", comment: "")
        }
        // used if cocoapods
        if let path = Bundle(for: Authentication.self).path(forResource: "io.hanko.FidoUafClientiOS", ofType: "bundle") {
            if let bundle = Bundle(path: path) {
                operationPrompt = NSLocalizedString("biomentryOperationPromptReg", tableName: "fidouafclient", bundle: bundle, value: "", comment: "")
            }
        }
        let overrideString = NSLocalizedString("biomentryOperationPromptReg", comment: "")
        if (overrideString != "biomentryOperationPromptReg") {
            operationPrompt = overrideString
        }
        
        return operationPrompt
    }

    private func getUafV1Krd(keyId: String, finalChallenge: String) throws -> Data {
        var value = Data()
        value.append(contentsOf: getAaidTag())
        value.append(contentsOf: getAssertionInfoTag())
        value.append(contentsOf: getFinalChallengeTag(finalChallenge: finalChallenge))
        value.append(contentsOf: getKeyIdTag(keyId: keyId))
        value.append(contentsOf: getCountersTag())
        value.append(contentsOf: try getPublicKeyTag())

        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_UAFV1_KRD.rawValue))
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }
    
    private func getAttestationTag(signedData: Data) throws -> Data {
        var signatureData = Data()
        signatureData.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_SIGNATURE.rawValue))

        let signatureValue = try self.ecManager.sign(signedData)
        signatureData.append(contentsOf: UnsignedUtil.encodeInt(int: signatureValue.count))
        signatureData.append(contentsOf: signatureValue)

        var surrogateTag = Data()
        surrogateTag.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_ATTESTATION_BASIC_SURROGATE.rawValue))
        surrogateTag.append(contentsOf: UnsignedUtil.encodeInt(int: signatureData.count))
        surrogateTag.append(contentsOf: signatureData)

        return surrogateTag
    }

    private func getAaidTag() -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_AAID.rawValue))

        let value = "A4A4#0002".data(using: .utf8)!
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }
    
    private func getKeyIdTag(keyId: String) -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_KEYID.rawValue))

        let value = keyId.data(using: .utf8)!
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }

    private func getFinalChallengeTag(finalChallenge: String) -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_FINAL_CHALLENGE.rawValue))

        let value = Hash.sha256(data: finalChallenge.data(using: .utf8)!)
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }

    private func getCountersTag() -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_COUNTERS.rawValue))

        data.append(contentsOf: UnsignedUtil.encodeInt(int: 8))
        data.append(contentsOf: UnsignedUtil.encodeInt32(int: 0))
        data.append(contentsOf: UnsignedUtil.encodeInt32(int: 0))

        return data
    }

    private func getPublicKeyTag() throws -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_PUB_KEY.rawValue))

        let value = try self.ecManager.publicKey().data().rawWithHeaders
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }

    private func getAssertionInfoTag() -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_ASSERTION_INFO.rawValue))
        // all values in littleEndian-format
        // 2 byte = Vendor assigned authenticator version
        // 1 byte = For Registration this must be 0x01 indicating that the user has explicitly verified the action.
        // 2 byte = Signature Algorithm and Encoding of the attestation signature.
        // 2 byte = Public Key algorithm and encoding of the newly generated UAuth.pub key.
        let value = Data(bytes: [0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00])
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }
}

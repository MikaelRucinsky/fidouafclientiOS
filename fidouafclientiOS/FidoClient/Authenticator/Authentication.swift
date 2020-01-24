import Foundation
import Security

class Authentication {

    var ecManager: EllipticCurveKeyPair.Manager!

    init() {}

    func process(authRequest: AuthenticationRequest, finalChallenge: String, appId: String) -> AuthenticatorSignAssertion? {
        do {
            let keyIds: [String] = authRequest.policy.accepted.flatMap { mcArray in
                mcArray.flatMap { mc in
                    mc.keyIDs!.map { $0 } // TODO:
                }
            }

            let storedKeyIds = Storage.getKeyIds(appId: appId)

            let resolvedKeyIds = storedKeyIds.filter { keyIds.contains($0) }
            if (resolvedKeyIds.count <= 0) {
                return nil
            }

            let transaction = getTransaction(transactions: authRequest.transaction)

            var operationPrompt: String = getOperationPrompt()
            if let transact = transaction {
                operationPrompt = transact.content.base64UrlWithoutPaddingDecoded()!
            }

            let ecHelper = EllipticCurveKeyPair.Helper(
                    publicLabel: Utils.generatePublicLabel(appId: appId, keyId: resolvedKeyIds[0]),
                    privateLabel: Utils.generatePrivateLabel(appId: appId, keyId: resolvedKeyIds[0]),
                    operationPrompt: operationPrompt,
                    sha256: Hash.sha256,
                    accessControl: try! EllipticCurveKeyPair.Helper.createAccessControl(protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags: Utils.generateAccessControlCreateFlags()))

            self.ecManager = EllipticCurveKeyPair.Manager(helper: ecHelper)

            let uafV1SignedDataTag = getUafV1SignedDataTag(keyId: resolvedKeyIds[0], finalChallenge: finalChallenge, transaction: transaction)
            let signatureTag = try getSignatureTag(signedData: uafV1SignedDataTag)

            var data = Data()
            data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_UAFV1_AUTH_ASSERTION.rawValue))
            data.append(contentsOf: UnsignedUtil.encodeInt(int: uafV1SignedDataTag.count + signatureTag.count))
            data.append(contentsOf: uafV1SignedDataTag)
            data.append(contentsOf: signatureTag)

            return AuthenticatorSignAssertion(
                    assertionScheme: "UAFV1TLV",
                    assertion: data.base64UrlWithoutPaddingEncodedString(removeBackslash: false),
                    exts: [])

        } catch let error {
            debugPrint("Failure while generating Authenticator Authentication response: \(error)")
        }
        return nil
    }
    
    private func getOperationPrompt() -> String {
        var operationPrompt = ""
        // used if carthage
        if let bundle = Bundle(identifier: "io.hanko.FidoUafClientiOS") {
            operationPrompt = NSLocalizedString("biomentryOperationPromptAuth", tableName: "fidouafclient", bundle: bundle, value: "", comment: "")
        }
        // used if cocoapods
        if let path = Bundle(for: Authentication.self).path(forResource: "io_hanko_fidouafclientios", ofType: "bundle") {
            if let bundle = Bundle(path: path) {
                operationPrompt = NSLocalizedString("biomentryOperationPromptAuth", tableName: "fidouafclient", bundle: bundle, value: "", comment: "")
            }
        }
        let overrideString = NSLocalizedString("biomentryOperationPromptAuth", comment: "")
        if (overrideString != "biomentryOperationPromptAuth") {
            operationPrompt = overrideString
        }
        
        return operationPrompt
    }
    
    private func getTransaction(transactions: [Transaction]) -> Transaction? {
        if (transactions.count > 0) {
            let filteredTransactions = transactions.filter { transaction in if (transaction.contentType == "text/plain") { return true } else { return false } }
            if (filteredTransactions.count > 0) {
                return filteredTransactions[0]
            }
        }
        return nil
    }
    
    private func getUafV1SignedDataTag(keyId: String, finalChallenge: String, transaction: Transaction?) -> Data {
        var value = Data()
        value.append(getAaidTag())
        value.append(getAssertionInfoTag(transaction: transaction))
        value.append(getAuthenticatorNonceTag())
        value.append(getFinalChallengeTag(finalChallenge: finalChallenge))
        value.append(getTransactionContentHashTag(transaction: transaction))
        value.append(getKeyIdTag(keyId: keyId))
        value.append(getCountersTag())

        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_UAFV1_SIGNED_DATA.rawValue))
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }

    private func getAaidTag() -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_AAID.rawValue))

        let value = AuthenticatorMetadata.authenticator.aaid.data(using: .utf8)!
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }

    private func getAssertionInfoTag(transaction: Transaction?) -> Data {
        var authenticationMode: UInt8 = 0x01
        if let _ = transaction {
            authenticationMode = 0x02
        }

        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_ASSERTION_INFO.rawValue))
        // all values in littleEndian-format
        // 2 byte = Vendor assigned authenticator version
        // 1 byte = Authentication Mode indicating whether user explicitly verified or not and indicating if there is a transaction content or not.
        // 2 byte = Signature Algorithm and Encoding of the attestation signature.
        let value: [UInt8] = [0x01, 0x00, authenticationMode, 0x01, 0x00]
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }

    private func getAuthenticatorNonceTag() -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_AUTHENTICATOR_NONCE.rawValue))
        let value = Utils.getRandomBytes(length: 8)!
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

    private func getTransactionContentHashTag(transaction: Transaction?) -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_TRANSACTION_CONTENT_HASH.rawValue))
        if let transact = transaction {
            let value = Hash.sha256(data: transact.content.base64UrlWithoutPaddingDecoded()!.data(using: .utf8)!)
            data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
            data.append(contentsOf: value)
        } else {
            data.append(contentsOf: UnsignedUtil.encodeInt(int: 0))
        }
        return data
    }

    private func getKeyIdTag(keyId: String) -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_KEYID.rawValue))
        let value: Data = keyId.base64UrlWithoutPaddingDecoded()!
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }

    private func getCountersTag() -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_COUNTERS.rawValue))
        data.append(contentsOf: UnsignedUtil.encodeInt(int: 4))
        data.append(contentsOf: UnsignedUtil.encodeInt32(int: 0))

        return data
    }

    private func getSignatureTag(signedData: Data) throws -> Data {
        var data = Data()
        data.append(contentsOf: UnsignedUtil.encodeInt(int: TagsEnum.TAG_SIGNATURE.rawValue))
        let value = try ecManager.sign(signedData)
        data.append(contentsOf: UnsignedUtil.encodeInt(int: value.count))
        data.append(contentsOf: value)

        return data
    }
}

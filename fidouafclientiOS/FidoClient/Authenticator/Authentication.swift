import Foundation
import Security

class Authentication: NSObject, UIPickerViewDelegate, UIPickerViewDataSource {
    func numberOfComponents(in pickerView: UIPickerView) -> Int {
        return 1
    }
    
    func pickerView(_ pickerView: UIPickerView, numberOfRowsInComponent component: Int) -> Int {
        return usernames.count
    }
    
    func pickerView(_ pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String? {
        return usernames[row]
    }
    
    func pickerView(_ pickerView: UIPickerView, didSelectRow row: Int, inComponent component: Int) {
        username = usernames[row]
    }
    
    var usernames: [String] = []
    var username: String = ""

    var ecManager: EllipticCurveKeyPair.Manager!

    override init() {}
    
    private var alertWindow: UIWindow {
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = ClearViewController()
        window.backgroundColor = UIColor.clear
        window.windowLevel = UIWindow.Level.alert
        
        return window
    }
    
    private static var alertController: AlertController? = nil
    
    func process(authRequest: AuthenticationRequest, finalChallenge: String, appId: String, completionHandler: @escaping (AuthenticatorSignAssertion?, FidoError) -> Void) {
        
        let userAndKeyIds = getUsernamesAndKeyIds(policy: authRequest.policy, appId: appId)
        
        guard userAndKeyIds.count > 0 else {
            completionHandler(nil, .NO_SUITABLE_AUTHENTICATOR)
            return
        }
        
        if (userAndKeyIds.count == 1) {
            let keyId = userAndKeyIds.first!.value
            let response = process(authRequest: authRequest, finalChallenge: finalChallenge, appId: appId, keyId: keyId)
            completionHandler(response, .NO_ERROR)
            return
        } else {
            usernames = Array(userAndKeyIds.keys)
            
            let viewController = UIViewController()
            viewController.preferredContentSize = CGSize(width: 250, height: 300)
            let pickerView = UIPickerView(frame: CGRect(x: 0, y: 0, width: 250, height: 300))
            pickerView.delegate = self
            pickerView.dataSource = self
            viewController.view.addSubview(pickerView)
            
            Authentication.alertController = AlertController(title: "Choose account", message: nil, preferredStyle: .alert)
            Authentication.alertController?.setValue(viewController, forKey: "contentViewController")
            Authentication.alertController?.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: { _ in
                    Authentication.self.alertController = nil
                    Authentication.self.alertController?.alertWindow = nil
                    completionHandler(nil, .USER_CANCELLED)
                }))
            Authentication.alertController?.addAction(UIAlertAction(title: "Done", style: .default, handler: { _ in
                Authentication.self.alertController = nil
                Authentication.self.alertController?.alertWindow = nil
                if let keyId = userAndKeyIds[self.username] {
                    let response = self.process(authRequest: authRequest, finalChallenge: finalChallenge, appId: appId, keyId: keyId)
                    completionHandler(response, .NO_ERROR)
                } else {
                    completionHandler(nil, .NO_SUITABLE_AUTHENTICATOR)
                    return
                }
            }))
            
            Authentication.alertController?.show()
            
//            if let rootViewController = alertWindow.rootViewController {
//                alertWindow.makeKeyAndVisible()
//
//                rootViewController.present(alertController, animated: true, completion: nil)
//            } else {
//                completionHandler(nil, .UNKNOWN)
//                return
//            }
        }
    }

    func process(authRequest: AuthenticationRequest, finalChallenge: String, appId: String, keyId: String) -> AuthenticatorSignAssertion? {
        do {
            let transaction = getTransaction(transactions: authRequest.transaction ?? [])

            var operationPrompt: String = getOperationPrompt()
            if let transact = transaction {
                operationPrompt = transact.content.base64UrlWithoutPaddingDecoded()!
            }

            let ecHelper = EllipticCurveKeyPair.Helper(
                    publicLabel: Utils.generatePublicLabel(appId: appId, keyId: keyId),
                    privateLabel: Utils.generatePrivateLabel(appId: appId, keyId: keyId),
                    operationPrompt: operationPrompt,
                    sha256: Hash.sha256,
                    accessControl: try! EllipticCurveKeyPair.Helper.createAccessControl(protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags: Utils.generateAccessControlCreateFlags()))

            self.ecManager = EllipticCurveKeyPair.Manager(helper: ecHelper)

            let uafV1SignedDataTag = getUafV1SignedDataTag(keyId: keyId, finalChallenge: finalChallenge, transaction: transaction)
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
    
    private func getUsernamesAndKeyIds(policy: Policy, appId: String) -> [String: String] {
        // get only matchCriteria with length of 1, because this client/authenticator supports only this authenticator
        let allowedMatchCriteria = policy.accepted.filter { $0.count == 1 }.flatMap { $0 }
        // filter only for our authenticator
        let allowed = allowedMatchCriteria.filter { $0.matchesAuthenticator(authenticator: AuthenticatorMetadata.authenticator) }
        
        let disallowed = policy.disallowed?.filter { $0.matchesAuthenticator(authenticator: AuthenticatorMetadata.authenticator) } ?? []
        guard disallowed.count == 0 && allowed.count > 0 else { return [:] }
        
        let allowedKeyIds = allowed.flatMap { $0.keyIDs ?? [] }
        
        guard let stored = Storage.load(appId: appId) else { return [:] }
        if (allowedKeyIds.count > 0) {
            return stored.filter { key, value in allowedKeyIds.contains(value) }
        } else {
            guard stored.count > 0 else { return [:] }
            return stored
        }
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
        // 1 byte = Authentication Mode indicating whether user explicitly verified or not and indicating if there is a transaction content or not. => 0x01 = Authentication | 0x02 = Transaction Confirmation
        // 2 byte = Signature Algorithm and Encoding of the attestation signature. => 0x0002 -> ALG_SIGN_SECP256R1_ECDSA_SHA256_DER
        let value: [UInt8] = [0x01, 0x00, authenticationMode, 0x02, 0x00]
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

private class ClearViewController: UIViewController {
    
    override var preferredStatusBarStyle: UIStatusBarStyle {
        return UIApplication.shared.statusBarStyle
    }
    
    override var prefersStatusBarHidden: Bool {
        return UIApplication.shared.isStatusBarHidden
    }
}

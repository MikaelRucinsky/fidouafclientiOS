import Foundation

public class FidoClient {

    public static func process(uafMessage: UAFMessage, channelBinding: ChannelBinding? = nil, sourceApplication: String? = nil) throws -> UAFMessage? {
        let protocolMessageArray = UafProtocolRequest.toArray(string: uafMessage.uafProtocolMessage)
        if (protocolMessageArray.count <= 0 || !UafProtocolRequest.validate(requests: protocolMessageArray)) {
            throw InternalError.FIDO_Protocol_Error
        }
        
        guard UafProtocolRequest.validateVersion(requests: protocolMessageArray) else { throw InternalError.FIDO_Unsupported_Version }
        
        var appID = protocolMessageArray[0].header.appID
        if (appID == nil || appID!.isEmpty) {
            appID = Utils.getFacetId(sourceApplication: sourceApplication)
        }
        
        guard appID?.count ?? 0 <= 512 else {
            throw InternalError.FIDO_Untrusted_Facet_Id
        }
        // TODO: if appID is an 'https' url than get trustedFacetList from that and check if sourceApplication is in trustedFacetList
//        URLSession.shared.dataTask(with: URL(string: "")!) { data, response, error in
//            (response as? HTTPURLResponse)?.statusCode
//            TrustedFacets.getArrayFromData(data: data)
//        }
        
        if (protocolMessageArray[0].header.op == Operation.Reg) {
            let registrationRequests = RegistrationRequest.toObject(string: uafMessage.uafProtocolMessage)
            guard registrationRequests.count > 0 else { throw InternalError.FIDO_Protocol_Error }
            if let regReq = registrationRequests[0] {
                guard Utils.validatePolicy(policy: regReq.policy) else { throw InternalError.FIDO_Protocol_Error }
                let finalChallenge = FinalChallengeParams(appID: appID!, challenge: regReq.challenge, facetID: Utils.getFacetId(sourceApplication: sourceApplication), channelBinding: channelBinding ?? ChannelBinding(serverEndPoint: nil, tlsServerCertificate: nil, tlsUnique: nil, cid_pubKey: nil))

                guard let finalChallengeString = finalChallenge.toBase64UrlStringWithoutPadding() else { return nil }
                guard let authenticatorRegistrationAssertion = Registration().process(regRequest: regReq, finalChallenge: finalChallengeString, appId: appID!) else { throw FidoClientError.NotAuthenticated }

                return RegistrationResponse(
                        header: regReq.header,
                        fcParams: finalChallengeString,
                        assertions: [authenticatorRegistrationAssertion]
                    ).toArrayString().map { UAFMessage(uafProtocolMessage: $0) }
            }
        } else if (protocolMessageArray[0].header.op == Operation.Auth) {
            let authenticationRequests = AuthenticationRequest.toObject(string: uafMessage.uafProtocolMessage)
            guard authenticationRequests.count > 0 else { throw InternalError.FIDO_Protocol_Error }
            if let authReq = authenticationRequests[0] {
                guard Utils.validatePolicy(policy: authReq.policy) else { throw InternalError.FIDO_Protocol_Error }
                let finalChallenge = FinalChallengeParams(appID: appID!, challenge: authReq.challenge, facetID: Utils.getFacetId(sourceApplication: sourceApplication), channelBinding: channelBinding ?? ChannelBinding(serverEndPoint: nil, tlsServerCertificate: nil, tlsUnique: nil, cid_pubKey: nil))

                guard let finalChallengeString = finalChallenge.toBase64UrlStringWithoutPadding() else { return nil }
                guard let authenticatorSignAssertion = Authentication().process(authRequest: authReq, finalChallenge: finalChallengeString, appId: appID!) else { throw FidoClientError.NotAuthenticated }

                return AuthenticationResponse(
                        header: authReq.header,
                        fcParams: finalChallengeString,
                        assertions: [authenticatorSignAssertion]
                ).toArrayString().map { UAFMessage(uafProtocolMessage: $0) }
            }
        } else if (protocolMessageArray[0].header.op == Operation.Dereg) {
            let deregistrationRequests = DeregistrationRequest.toObject(string: uafMessage.uafProtocolMessage)
            guard deregistrationRequests.count > 0 else { throw InternalError.FIDO_Protocol_Error }
            if let deregReq = deregistrationRequests[0] {
                Deregistration().process(deregRequest: deregReq, appId: appID!)
            }
            return nil
        }
        return nil
    }
    
    public static func process(url: URL, sourceApplication: String?) -> URL? {
        do {
            guard let xCallbackUrlData = try url.extractXCallbackUrlData() else { return nil }
            
            print("Input: \(xCallbackUrlData.json)")

            switch xCallbackUrlData.requestType {
            case .UAF_OPERATION:
                if let responseData = try processUafOperation(xCallbackUrlData: xCallbackUrlData, sourceApplication: sourceApplication) {
                    return try generateResponseUrl(xCallbackUrlData: xCallbackUrlData, value: responseData)
                }
            case .CHECK_POLICY:
                processCheckPolicyRequest()
            case .DISCOVER:
                processDiscoveryRequest()
            case .UAF_OPERATION_COMPLETION_STATUS:
                return nil
            default:
                return nil
            }
        } catch {
            print("Lib \(error)")
        }
        
        return nil
    }
    
    private static func processUafOperation(xCallbackUrlData: XCallbackUrlData, sourceApplication: String?) throws -> Data? {
        if let json = xCallbackUrlData.json {
            let uafUrlMessage = try decode(XCallbackUafOperationRequestData.self, from: json.base64UrlWithoutPaddingDecoded()!)
            let uafMessage = try decode(UAFMessage.self, from: uafUrlMessage.message)
            let channelBindings = try decode(ChannelBinding.self, from: uafUrlMessage.channelBindings)
            
            var resultValue: XCallbackUrlUafOperationResultData? = nil
            do {
                let result = try process(uafMessage: uafMessage, channelBinding: channelBindings, sourceApplication: sourceApplication)
                if let r = result {
                    resultValue = XCallbackUrlUafOperationResultData(errorCode: FidoError.NO_ERROR.rawValue, message: String(data: try JSONEncoder().encode(r), encoding: .utf8))
                } else {
                    resultValue = XCallbackUrlUafOperationResultData(errorCode: FidoError.UNKNOWN.rawValue, message: nil)
                }
            } catch InternalError.FIDO_Protocol_Error {
                resultValue = XCallbackUrlUafOperationResultData(errorCode: FidoError.PROTOCOL_ERROR.rawValue, message: nil)
            } catch InternalError.FIDO_Unknown {
                resultValue = XCallbackUrlUafOperationResultData(errorCode: FidoError.UNKNOWN.rawValue, message: nil)
            } catch InternalError.FIDO_User_Cancelled {
                resultValue = XCallbackUrlUafOperationResultData(errorCode: FidoError.USER_CANCELLED.rawValue, message: nil)
            } catch InternalError.FIDO_Untrusted_Facet_Id {
                resultValue = XCallbackUrlUafOperationResultData(errorCode: FidoError.UNTRUSTED_FACET_ID.rawValue, message: nil)
            } catch InternalError.FIDO_No_Suitable_Authenticator {
                resultValue = XCallbackUrlUafOperationResultData(errorCode: FidoError.NO_SUITABLE_AUTHENTICATOR.rawValue, message: nil)
            } catch InternalError.FIDO_Unsupported_Version {
                resultValue = XCallbackUrlUafOperationResultData(errorCode: FidoError.UNSUPPORTED_VERSION.rawValue, message: nil)
            } catch InternalError.FIDO_Key_Disappeared_Permanently {
                resultValue = XCallbackUrlUafOperationResultData(errorCode: FidoError.KEY_DISAPPEARED_PERMANENTLY.rawValue, message: nil)
            }
            print("resultValue: \(resultValue)")
            return try JSONEncoder().encode(resultValue)
        }
        return nil
    }
    
    private static func generateResponseUrl(xCallbackUrlData: XCallbackUrlData, value unencryptedValue: Data) throws -> URL? {
        let base64EncodedKey = xCallbackUrlData.secretKey.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = base64EncodedKey.count % 4
        let base64EncodedKeyWithPadding = base64EncodedKey.padding(toLength: base64EncodedKey.count + (4 - remainder) % 4, withPad: "=", startingAt: 0)
        
        guard let secretKeyData = Data(base64Encoded: base64EncodedKeyWithPadding) else {
            print("Encryption: secretKeyData could not be extracted")
            return nil
        }
        guard let encryptedValue = A128CBCHS256_encDir(plaintext: unencryptedValue, secretKey: secretKeyData) else {
            print("Encryption: response could not be encrypted")
            return nil
        }
        
        let encryptedValueData = try JSONEncoder().encode(encryptedValue)
        let base64EncryptedValue = encryptedValueData.base64UrlWithoutPaddingEncodedString(removeBackslash: false)
        
        var returnUrl = URLComponents(string: xCallbackUrlData.xSuccessUrl)
        var queryItems: [URLQueryItem] = []
        if let state = xCallbackUrlData.state {
            queryItems.append(URLQueryItem(name: "state", value: state))
        }
        queryItems.append(URLQueryItem(name: "json", value: base64EncryptedValue))
        returnUrl?.queryItems = queryItems
        
        if let url = returnUrl {
            return URL(string: url.url!.absoluteString.replacingOccurrences(of: "?", with: "&")) // replace queryItems delimiter character because of FIDO Alliance Conformance Tool bug, which will not be fixed: https://github.com/fido-alliance/conformance-tools-issues/issues/510
        } else {
            return nil
        }
    }
    
    private static func decode<T>(_ type: T.Type, from string: String) throws -> T where T : Decodable {
        guard let data = string.data(using: .utf8) else { throw InternalError.Default("Data could not be crated from string") }
        let decoder = JSONDecoder()
        return try decoder.decode(type, from: data)
    }
    
    // encrypt response with given key
    private static func A128CBCHS256_encDir(plaintext: Data, secretKey: Data) -> XCallbackUrlJweResponse? {
        // validate secret key
        guard secretKey.count == 32 else {
            print("SecretKey not validated: \(secretKey.count)")
            return nil
        }
        // generate random iv
        guard let iv = Utils.getRandomBytes(length: 16) else {
            print("iv not generated")
            return nil
        }
        
        let macKey = secretKey[0..<16]
        let encKey = secretKey[16..<secretKey.count]
        
        // encrypt plaintext
        var encryptedByteCount: Int = 0
        var ciphertext = [UInt8](repeating: 0, count: iv.count + plaintext.count + kCCBlockSizeAES128)
        
        let status = encKey.withUnsafeBytes { encKeyBytes in
            iv.withUnsafeBytes { ivBytes in
                plaintext.withUnsafeBytes { plaintextBytes in
                    return CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        encKeyBytes.baseAddress,
                        kCCKeySizeAES128,
                        ivBytes.baseAddress,
                        plaintextBytes.baseAddress,
                        plaintext.count,
                        &ciphertext,
                        ciphertext.count,
                        &encryptedByteCount
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            print("CCCryptStatus: \(status)")
            return nil }
        
        let ciphertextData = Data(bytes: UnsafePointer<UInt8>(ciphertext), count: encryptedByteCount)
        
//        ciphertext.count = cryptBytes
        
        // compute AL (there is no AAD, so AL is a 64-bit string of zeros - normally it would be the number of bits of AAD expressed as big-endian)
        let al: [UInt8] = [ 0, 0, 0, 0, 0, 0, 0, 0 ]
        let alData = Data(bytes: al)
        
        // compute HMAC-SHA256 over IV + ciphertext + AL
        let hmacData = NSMutableData()
        hmacData.append(iv)
        hmacData.append(ciphertextData)
        hmacData.append(alData)
        
        let mac = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(CC_SHA256_DIGEST_LENGTH))
        macKey.withUnsafeBytes { macKeyBytes in
            (hmacData as Data).withUnsafeBytes { hmacDataBytes in
                CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA256),
                    macKeyBytes,
                    macKey.count,
                    hmacDataBytes.baseAddress,
                    hmacData.count,
                    mac
                )
            }
        }
        
        let macData = Data(bytes: mac, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        // truncate the mac (first 16 bytes only) to become the tag
        let tagData: Data = macData[0..<16]
        
        return XCallbackUrlJweResponse(
            unprotected: XCallbackUrlJweHeader(alg: "dir", enc: "A128CBC-HS256"),
            iv: iv.base64UrlWithoutPaddingEncodedString(removeBackslash: false),
            ciphertext: ciphertextData.base64UrlWithoutPaddingEncodedString(removeBackslash: false),
            tag: tagData.base64UrlWithoutPaddingEncodedString(removeBackslash: false)
        )
    }
    
    private static func processDiscoveryRequest() {
        
    }
    
    private static func processCheckPolicyRequest() {
        
    }
    
    private static func processUafOperationCompletionStatus() {
        
    }
}

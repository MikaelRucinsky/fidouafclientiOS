import Foundation

public class FidoClient {

    public static func process(uafMessage: UAFMessage, channelBinding: ChannelBinding? = nil, skipTrustedFacetVerification: Bool = false, sourceApplication: String? = nil, completionHandler: @escaping (UAFMessage?, FidoError) -> Void) {
        let protocolMessageArray = UafProtocolRequest.toArray(string: uafMessage.uafProtocolMessage)
        if (protocolMessageArray.count <= 0 || !UafProtocolRequest.validate(requests: protocolMessageArray)) {
            completionHandler(nil, .PROTOCOL_ERROR)
            return
        }
        
        guard UafProtocolRequest.validateVersion(requests: protocolMessageArray) else {
            completionHandler(nil, .UNSUPPORTED_VERSION)
            return
        }
        guard UafProtocolRequest.validateUnknownExtensions(requests: protocolMessageArray) else {
            completionHandler(nil, .UNKNOWN)
            return
        }
        
        let facetId = Utils.getFacetId(sourceApplication: sourceApplication)
        
        var appID = protocolMessageArray[0].header.appID
        if (appID == nil || appID!.isEmpty) {
            appID = Utils.getFacetId(sourceApplication: sourceApplication) // set appID to facetID
        }
        
        guard appID?.count ?? 0 <= 512 else {
            completionHandler(nil, .PROTOCOL_ERROR)
            return
        }
        
        if (!skipTrustedFacetVerification) {
            if (appID!.starts(with: "ios:bundle-id:") && appID! == facetId) {
                process(operation: protocolMessageArray[0].header.op, uafMessage: uafMessage, channelBinding: channelBinding, appID: appID!, sourceApplication: sourceApplication, completionHandler: completionHandler)
            } else if (appID!.starts(with: "https")) {
                HttpService.getTrustedFacetsFromServer(appID!) { trustedFacetList in
                    if (appID!.starts(with: "https") && trustedFacetList == nil) {
                        completionHandler(nil, .UNTRUSTED_FACET_ID)
                        return
                    }
                    
                    if let list = trustedFacetList {
                        guard Utils.checkTrustedFacetList(trustedFacetList: list, sourceApplication: sourceApplication!) else {
                            completionHandler(nil, .UNTRUSTED_FACET_ID)
                            return
                        }
                    }
                    process(operation: protocolMessageArray[0].header.op, uafMessage: uafMessage, channelBinding: channelBinding, appID: appID!, sourceApplication: sourceApplication, completionHandler: completionHandler)
                }
            } else {
                completionHandler(nil, .UNTRUSTED_FACET_ID)
                return
            }
        } else {
            process(operation: protocolMessageArray[0].header.op, uafMessage: uafMessage, channelBinding: channelBinding, appID: appID!, sourceApplication: sourceApplication, completionHandler: completionHandler)
        }
    }
    
    private static func process(operation: Operation, uafMessage: UAFMessage, channelBinding: ChannelBinding?, appID: String, sourceApplication: String?, completionHandler: @escaping (UAFMessage?, FidoError) -> Void) {
        switch operation {
            case .Reg: FidoClientOperations.processRegistration(uafMessage: uafMessage, channelBinding: channelBinding, appID: appID, sourceApplication: sourceApplication, completionHandler: completionHandler)
            case .Auth:
                FidoClientOperations.processAuthentication(uafMessage: uafMessage, channelBinding: channelBinding, appID: appID, sourceApplication: sourceApplication, completionHandler: completionHandler)
            case .Dereg:
                FidoClientOperations.processDeregistration(uafMessage: uafMessage, appID: appID, completionHandler: completionHandler)
        }
    }
    
    public static func process(url: URL, sourceApplication: String?, completionHandler: @escaping (URL?) -> Void) {
        do {
            guard let xCallbackUrlData = try url.extractXCallbackUrlData() else {
                completionHandler(nil)
                return
            }

            switch xCallbackUrlData.requestType {
                case .UAF_OPERATION:
                    // TODO:
                    processUafOperation(xCallbackUrlData: xCallbackUrlData, sourceApplication: sourceApplication) { responseData in
                        do {
                            if let data = responseData {
                                completionHandler(try generateResponseUrl(xCallbackUrlData: xCallbackUrlData, value: data))
                                return
                            } else {
                                completionHandler(nil)
                                return
                            }
                        } catch {
                            completionHandler(nil)
                            return
                        }
                    }
                case .CHECK_POLICY:
                    processCheckPolicyRequest(xCallbackUrlData: xCallbackUrlData) { responseData in
                        do {
                            if let data = responseData {
                                completionHandler(try generateResponseUrl(xCallbackUrlData: xCallbackUrlData, value: data))
                                return
                            } else {
                                completionHandler(nil)
                                return
                            }
                        } catch {
                            completionHandler(nil)
                            return
                        }
                    }
                    completionHandler(nil)
                    return
                case .DISCOVER:
                    processDiscoveryRequest(xCallbackUrlData: xCallbackUrlData) { responseData in
                        do {
                            if let data = responseData {
                                completionHandler(try generateResponseUrl(xCallbackUrlData: xCallbackUrlData, value: data))
                                return
                            } else {
                                completionHandler(nil)
                                return
                            }
                        } catch {
                            completionHandler(nil)
                            return
                        }
                    }
                    completionHandler(nil)
                    return
                case .UAF_OPERATION_COMPLETION_STATUS:
                    completionHandler(nil)
                    return
                default:
                    completionHandler(nil)
                    return
            }
        } catch {
            print("\(error)")
            completionHandler(nil)
            return
        }
    }
    
    private static func processUafOperation(xCallbackUrlData: XCallbackUrlData, sourceApplication: String?, completionHandler: @escaping (Data?) -> Void ) {
        do {
            if let json = xCallbackUrlData.json {
                let uafUrlMessage = try decode(XCallbackUafOperationRequestData.self, from: json.base64UrlWithoutPaddingDecoded()!)
                let uafMessage = try decode(UAFMessage.self, from: uafUrlMessage.message)
                let channelBindings = try decode(ChannelBinding.self, from: uafUrlMessage.channelBindings)
                
                process(uafMessage: uafMessage, channelBinding: channelBindings, sourceApplication: sourceApplication) { result, error in
                    do {
                        var resultMessage: XCallbackUrlUafOperationResultData? = nil
                        
                        if let r = result {
                            resultMessage = XCallbackUrlUafOperationResultData(errorCode: error.rawValue, message: String(data: try JSONEncoder().encode(r), encoding: .utf8))
                        } else {
                            resultMessage = XCallbackUrlUafOperationResultData(errorCode: error.rawValue, message: nil)
                        }
                        completionHandler(try JSONEncoder().encode(resultMessage))
                        return
                    } catch {
                        completionHandler(nil)
                        return
                    }
                }
            }
        } catch {
            completionHandler(nil)
            return
        }
        completionHandler(nil)
        return
    }
    
    private static func processDiscoveryRequest(xCallbackUrlData: XCallbackUrlData, completionHandler: @escaping (Data?) -> Void) {
        do {
            let discoveryData = DiscoveryData(supportedUAFVersions: AuthenticatorMetadata.supportedVersions, clientVendor: "Hanko", clientVersion: Version(major: 1, minor: 0), availableAuthenticators: [AuthenticatorMetadata.authenticator])
            
            let discoveryDataString = String(data: try JSONEncoder().encode(discoveryData), encoding: .utf8)
            
            let xCallbackUrlResult = XCallbackUrlDiscoveryResultData(errorCode: FidoError.NO_ERROR.rawValue, discoveryData: discoveryDataString!)
            let xCallbackUrlResultData = try JSONEncoder().encode(xCallbackUrlResult)
            
            completionHandler(xCallbackUrlResultData)
            return
        } catch {
            print("\(error)")
            completionHandler(nil)
            return
        }
    }
    
    private static func processCheckPolicyRequest(xCallbackUrlData: XCallbackUrlData, completionHandler: @escaping (Data?) -> Void) {
        do {
            if let json = xCallbackUrlData.json {
                let checkPolicyData = try decode(XCallbackUrlCheckPolicyRequestData.self, from: json.base64UrlWithoutPaddingDecoded()!)
                let uafMessage = try decode(UAFMessage.self, from: checkPolicyData.message)
                    
                let checkPolicyDataArray = CheckPolicyRequest.toObject(string: uafMessage.uafProtocolMessage)
                guard !checkPolicyDataArray.isEmpty else {
                    completionHandler(nil)
                    return
                }
                
                let checkPolicyRequest = checkPolicyDataArray[0]
                let accepted = checkPolicyRequest.policy.accepted.flatMap { array in array.map { $0.isValid() && $0.matchesAuthenticator(authenticator: AuthenticatorMetadata.authenticator) } }
                let acceptedResult = accepted.contains(true)
                let disallowedResult = checkPolicyRequest.policy.disallowed?.map { $0.matchesAuthenticator(authenticator: AuthenticatorMetadata.authenticator) }.contains(true) ?? false
                
                let errorCode = acceptedResult && !disallowedResult ? FidoError.NO_ERROR : FidoError.NO_SUITABLE_AUTHENTICATOR
                
                let xCallbackUrlResult = XCallbackUrlCheckPolicyResultData(errorCode: errorCode.rawValue)
                let xCallbackUrlResultData = try JSONEncoder().encode(xCallbackUrlResult)
                
                completionHandler(xCallbackUrlResultData)
                return
            } else {
                completionHandler(nil)
                return
            }
        } catch {
            print("\(error)")
            completionHandler(nil)
            return
        }
    }
    
    private static func processUafOperationCompletionStatus() {
        
    }
    
    private static func generateResponseUrl(xCallbackUrlData: XCallbackUrlData, value unencryptedValue: Data) throws -> URL? {
        let base64EncodedKey = xCallbackUrlData.secretKey.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = base64EncodedKey.count % 4
        let base64EncodedKeyWithPadding = base64EncodedKey.padding(toLength: base64EncodedKey.count + (4 - remainder) % 4, withPad: "=", startingAt: 0)
        
        guard let secretKeyData = Data(base64Encoded: base64EncodedKeyWithPadding) else {
            print("Encryption: secretKeyData could not be extracted")
            return nil
        }
        guard let encryptedValue = Utils.encryptResponse(plaintext: unencryptedValue, secretKey: secretKeyData) else {
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
}

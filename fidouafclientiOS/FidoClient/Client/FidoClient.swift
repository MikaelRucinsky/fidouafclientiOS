import Foundation

public class FidoClient {

    public static func process(uafMessage: UAFMessage, channelBinding: ChannelBinding? = nil) throws -> UAFMessage? {
        let protocolMessageArray = UafProtocolRequest.toArray(string: uafMessage.uafProtocolMessage)
        if (protocolMessageArray.count <= 0) {
            return nil
        }
        let message = uafMessage.uafProtocolMessage
        if (protocolMessageArray[0].header.op == Operation.Reg) {
            let registrationRequests = RegistrationRequest.toObject(string: message)
            guard registrationRequests.count > 0 else { return nil }
            if let regReq = registrationRequests[0] {
                var appID = regReq.header.appID
                if(appID.isEmpty) { appID = Utils.getFacetId() }
                let finalChallenge = FinalChallengeParams(appID: appID, challenge: regReq.challenge, facetID: Utils.getFacetId(), channelBinding: channelBinding ?? ChannelBinding(serverEndPoint: nil, tlsServerCertificate: nil, tlsUnique: nil, cid_pubKey: nil))

                guard let finalChallengeString = finalChallenge.toBase64UrlStringWithoutPadding() else { return nil }
                guard let authenticatorRegistrationAssertion = Registration().process(regRequest: regReq, finalChallenge: finalChallengeString) else { throw FidoClientError.NotAuthenticated }

                return RegistrationResponse(
                        header: regReq.header,
                        fcParams: finalChallengeString,
                        assertions: [authenticatorRegistrationAssertion]
                    ).toArrayString().map { UAFMessage(uafProtocolMessage: $0) }
            }
        } else if (protocolMessageArray[0].header.op == Operation.Auth) {
            let authenticationRequests = AuthenticationRequest.toObject(string: message)
            guard authenticationRequests.count > 0 else { return nil }
            if let authReq = authenticationRequests[0] {
                var appID = authReq.header.appID
                if(appID.isEmpty) { appID = Utils.getFacetId() }
                let finalChallenge = FinalChallengeParams(appID: appID, challenge: authReq.challenge, facetID: Utils.getFacetId(), channelBinding: channelBinding ?? ChannelBinding(serverEndPoint: nil, tlsServerCertificate: nil, tlsUnique: nil, cid_pubKey: nil))

                guard let finalChallengeString = finalChallenge.toBase64UrlStringWithoutPadding() else { return nil }
                guard let authenticatorSignAssertion = Authentication().process(authRequest: authReq, finalChallenge: finalChallengeString) else { throw FidoClientError.NotAuthenticated }

                return AuthenticationResponse(
                        header: authReq.header,
                        fcParams: finalChallengeString,
                        assertions: [authenticatorSignAssertion]
                ).toArrayString().map { UAFMessage(uafProtocolMessage: $0) }
            }
        } else if (protocolMessageArray[0].header.op == Operation.Dereg) {
            let deregistrationRequests = DeregistrationRequest.toObject(string: message)
            if let deregReq = deregistrationRequests[0] {
                Deregistration().process(deregRequest: deregReq)
            }
            return nil
        }
        return nil
    }
    
    public static func process(url: URL) -> URL? {
        do {
            let xCallbackUrlData = try url.extractXCallbackUrlData()
            guard xCallbackUrlData != nil else { return nil }
            if let json = xCallbackUrlData!.json {
                let uafUrlMessage = try decode(XCallbackUafOperationRequestData.self, from: json)
                let uafMessage = try decode(UAFMessage.self, from: uafUrlMessage.message)
                let channelBindings = try decode(ChannelBinding.self, from: uafUrlMessage.channelBindings)
                
                let result = try process(uafMessage: uafMessage, channelBinding: channelBindings)
                
                var returnUrl = URLComponents(string: xCallbackUrlData!.xSuccessUrl)
                var queryItems: [URLQueryItem] = []
                if let state = xCallbackUrlData!.state {
                    queryItems.append(URLQueryItem(name: "state", value: state))
                }
                if let resultJson = result {
                    let resultValue = XCallbackUrlUafOperationResultData(errorCode: 0, message: String(describing: try JSONEncoder().encode(resultJson))) // TODO: change errorCode
                    let unencryptedValue = try JSONEncoder().encode(queryValue)
                    queryItems.append(URLQueryItem(name: "json", value: try JSONEncoder().encode(queryValue).base64UrlWithoutPaddingEncodedString(removeBackslash: true))) // TODO: encrypt result and base64 encode it
                }
                
                returnUrl?.queryItems = queryItems
                return returnUrl?.url
            }
        } catch {
            NSLog("\(error)")
        }
        
        return nil
    }
    
    private static func decode<T>(_ type: T.Type, from string: String) throws -> T where T : Decodable {
        guard let data = string.data(using: .utf8) else { throw InternalError.Default("Data could not be crated from string") }
        let decoder = JSONDecoder()
        return try decoder.decode(type, from: data)
    }
    
    private static func processDiscoveryRequest() {
        
    }
    
    private static func processCheckPolicyRequest() {
        
    }
    
    private static func processUafOperationCompletionStatus() {
        
    }
}

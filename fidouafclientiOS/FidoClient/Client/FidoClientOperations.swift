import Foundation

class FidoClientOperations {
    static func processRegistration(uafMessage: UAFMessage, channelBinding: ChannelBinding?, appID: String, sourceApplication: String?, completionHandler: @escaping (UAFMessage?, FidoError) -> Void) {
        let registrationRequests = RegistrationRequest.toObject(string: uafMessage.uafProtocolMessage)
        guard registrationRequests.count > 0 else {
            completionHandler(nil, .PROTOCOL_ERROR)
            return
        }
        if let regReq = registrationRequests[0] {
            guard Utils.validatePolicy(policy: regReq.policy) else {
                completionHandler(nil, .PROTOCOL_ERROR)
                return
            }
            let finalChallenge = FinalChallengeParams(appID: appID, challenge: regReq.challenge, facetID: Utils.getFacetId(sourceApplication: sourceApplication), channelBinding: channelBinding ?? ChannelBinding(serverEndPoint: nil, tlsServerCertificate: nil, tlsUnique: nil, cid_pubKey: nil))

            guard let finalChallengeString = finalChallenge.toBase64UrlStringWithoutPadding() else {
                completionHandler(nil, .UNKNOWN)
                return
            }
            guard let authenticatorRegistrationAssertion = Registration().process(regRequest: regReq, finalChallenge: finalChallengeString, appId: appID) else {
                completionHandler(nil, .USER_CANCELLED) // NOT_AUTHENTICATED
                return
            }

            completionHandler(RegistrationResponse(
                    header: regReq.header,
                    fcParams: finalChallengeString,
                    assertions: [authenticatorRegistrationAssertion]
            ).toArrayString().map { UAFMessage(uafProtocolMessage: $0) }, .NO_ERROR)
            return
        }
        completionHandler(nil, .UNKNOWN)
        return
    }
    
    static func processAuthentication(uafMessage: UAFMessage, channelBinding: ChannelBinding?, appID: String, sourceApplication: String?, completionHandler: @escaping (UAFMessage?, FidoError) -> Void) {
        let authenticationRequests = AuthenticationRequest.toObject(string: uafMessage.uafProtocolMessage)
        guard authenticationRequests.count > 0 else {
            completionHandler(nil, .PROTOCOL_ERROR)
            return
        }
        if let authReq = authenticationRequests[0] {
            guard Utils.validatePolicy(policy: authReq.policy) else {
                completionHandler(nil, .PROTOCOL_ERROR)
                return
            }
            let invalidTransaction = authReq.transaction?.filter { $0.contentType.isEmpty || $0.content.isEmpty || $0.content.count > 200 || !Utils.isBase64UrlEncoded($0.content) } ?? []
            guard invalidTransaction.count == 0 else {
                completionHandler(nil, .PROTOCOL_ERROR)
                return
            }
            guard !authReq.challenge.isEmpty else {
                completionHandler(nil, .PROTOCOL_ERROR)
                return
            }
            let finalChallenge = FinalChallengeParams(appID: appID, challenge: authReq.challenge, facetID: Utils.getFacetId(sourceApplication: sourceApplication), channelBinding: channelBinding ?? ChannelBinding(serverEndPoint: nil, tlsServerCertificate: nil, tlsUnique: nil, cid_pubKey: nil))

            guard let finalChallengeString = finalChallenge.toBase64UrlStringWithoutPadding() else {
                completionHandler(nil, .UNKNOWN)
                return
            }
            Authentication().process(authRequest: authReq, finalChallenge: finalChallengeString, appId: appID) { authenticatorSignAssertion, error in
                if (error == .NO_ERROR && authenticatorSignAssertion != nil) {
                    completionHandler(AuthenticationResponse(
                            header: authReq.header,
                            fcParams: finalChallengeString,
                            assertions: [authenticatorSignAssertion!]
                    ).toArrayString().map { UAFMessage(uafProtocolMessage: $0) }, .NO_ERROR)
                    return
                } else if (error != .NO_ERROR) {
                    completionHandler(nil, error)
                    return
                } else {
                    completionHandler(nil, .UNKNOWN)
                }
            }
        } else {
            completionHandler(nil, .UNKNOWN)
            return
        }
    }
    
    static func processDeregistration(uafMessage: UAFMessage, appID: String, completionHandler: @escaping (UAFMessage?, FidoError) -> Void) {
        let deregistrationRequests = DeregistrationRequest.toObject(string: uafMessage.uafProtocolMessage)
        guard deregistrationRequests.count > 0 else {
            completionHandler(nil, .PROTOCOL_ERROR)
            return
        }
//        let wrongFormatedRequests = deregistrationRequests.filter { $0?.authenticators.contains(where: { deregAuth in deregAuth.aaid.isEmpty}) ?? false }
//        guard wrongFormatedRequests.count == 0 else {
//            completionHandler(nil, .PROTOCOL_ERROR)
//            return
//        }
        
        let wrongFormattedRequests = deregistrationRequests.filter { $0.authenticators.contains(where: { deregReq in
            if (!deregReq.aaid.isEmpty && !Utils.isValidAAID(deregReq.aaid)) {
                return true
            } else if (!deregReq.keyID.isEmpty && !Utils.isBase64UrlEncoded(deregReq.keyID)) {
                return true
            } else {
                return false
            }
        }) }
        guard wrongFormattedRequests.count == 0 else {
            completionHandler(nil, .PROTOCOL_ERROR)
            return
        }
        
        //if let deregReq = deregistrationRequests[0] {
            Deregistration().process(deregRequest: deregistrationRequests[0], appId: appID)
        //}
        completionHandler(UAFMessage(uafProtocolMessage: ""), .NO_ERROR)
        return
    }
}

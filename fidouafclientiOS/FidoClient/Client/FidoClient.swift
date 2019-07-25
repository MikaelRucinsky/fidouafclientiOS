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
}

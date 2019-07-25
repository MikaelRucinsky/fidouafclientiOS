import Foundation

struct FinalChallengeParams: Codable {

    let appID: String
    let challenge: String
    let facetID: String
    let channelBinding: ChannelBinding
}

extension FinalChallengeParams {

    func toBase64UrlStringWithoutPadding() -> String? {
        do {
            let jsonData = try JSONEncoder().encode(self)
            return jsonData.base64UrlWithoutPaddingEncodedString(removeBackslash: true)
        } catch let error {
            debugPrint("Serialization of FinalChallengeParams failed: \(error)")
        }
        return nil
    }
}

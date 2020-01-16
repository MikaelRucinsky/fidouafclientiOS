import Foundation

struct XCallbackUrlJsonData: Codable {
    let discoveryData: String?
    let errorCode: CShort?
    let message: String?
    let origin: String?
    let channelBindings: String?
    let responseCode: CShort?
}

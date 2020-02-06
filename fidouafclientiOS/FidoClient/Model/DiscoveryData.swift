import Foundation

struct DiscoveryData: Codable {
    let supportedUAFVersions: [Version]
    let clientVendor: String
    let clientVersion: Version
    let availableAuthenticators: [Authenticator]
}

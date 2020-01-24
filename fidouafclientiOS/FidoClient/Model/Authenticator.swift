import Foundation

struct Authenticator {
    let title: String
    let aaid: String
    let description: String
    let supportedUAFVersions: [Version]
    let assertionScheme: String
    let authenticationAlgorithm: Int
    let attestationTypes: [Int]
    let userVerification: Int64
    let keyProtection: Int
    let matcherProtection: Int
    let attachmentHint: Int
    let isSecondFactorOnly: Bool
    let tcDisplay: Int
    let tcDisplayContentType: String
    let tcDisplayPNGCharacteristics: DisplayPNGCharacteristicsDescriptor?
    let icon: String
    let supportedExtensionIDs: [String]
}

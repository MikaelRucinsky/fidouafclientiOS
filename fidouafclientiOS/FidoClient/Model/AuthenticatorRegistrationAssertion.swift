import Foundation

struct AuthenticatorRegistrationAssertion: Codable {

    let assertionScheme: String
    let assertion: String
    let tcDisplayPNGCharacteristics: [DisplayPNGCharacteristicsDescriptor]
    let exts: [Extension]
}

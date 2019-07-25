import Foundation

struct AuthenticatorSignAssertion: Codable {

    let assertionScheme: String
    let assertion: String
    let exts: [Extension]
}

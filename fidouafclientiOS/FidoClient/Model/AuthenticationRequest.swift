import Foundation

struct AuthenticationRequest: Codable {

    let header: OperationHeader
    let challenge: String
    let transaction: [Transaction]?
    let policy: Policy
}

extension AuthenticationRequest {
    
    static func toObject(string: String) -> [AuthenticationRequest?] {
        if let data = string.data(using: .utf8) {
            do {
                return try JSONDecoder().decode([AuthenticationRequest].self, from: data)
            } catch let error {
                debugPrint("Deserialization of AuthenticationRequest failed: \(error)") // TODO:
            }
        }
        return []
    }
}

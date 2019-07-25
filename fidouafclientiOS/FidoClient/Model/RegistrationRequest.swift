import Foundation

struct RegistrationRequest: Codable {

    let header: OperationHeader
    let challenge: String
    let username: String
    let policy: Policy
}

extension RegistrationRequest {

    static func toObject(string: String) -> [RegistrationRequest?] {
        if let data = string.data(using: .utf8) {
            do {
                return try JSONDecoder().decode([RegistrationRequest].self, from: data)
            } catch let error {
                debugPrint("Deserialization of RegistrationRequest failed: \(error)")
            }
        }
        return []
    }
}

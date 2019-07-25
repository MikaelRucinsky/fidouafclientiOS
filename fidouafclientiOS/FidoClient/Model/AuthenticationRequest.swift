import Foundation

struct AuthenticationRequest: Codable {

    let header: OperationHeader
    let challenge: String
    let transaction: [Transaction]
    let policy: Policy
}

extension AuthenticationRequest {
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        
        header = try values.decode(OperationHeader.self, forKey: .header)
        challenge = try values.decode(String.self, forKey: .challenge)
        transaction = (try? values.decode([Transaction].self, forKey: .transaction)) ?? []
        policy = try values.decode(Policy.self, forKey: .policy)
    }
    
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

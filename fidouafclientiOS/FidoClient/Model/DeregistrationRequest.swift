import Foundation

struct DeregistrationRequest: Codable {

    let header: OperationHeader
    let authenticators: [DeregisterAuthenticator]
}

extension DeregistrationRequest {
    
    static func toObject(string: String) -> [DeregistrationRequest] {
        if let data = string.data(using: .utf8) {
            do {
                return try JSONDecoder().decode([DeregistrationRequest].self, from: data)
            } catch let error {
                debugPrint("Deserialization of DeregistrationRequest failed: \(error)")
            }
        }
        return []
    }
}

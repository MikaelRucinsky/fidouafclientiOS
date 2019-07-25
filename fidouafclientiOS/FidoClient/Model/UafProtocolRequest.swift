import Foundation

struct UafProtocolRequest: Codable {
    let header: OperationHeader
}

extension UafProtocolRequest {
    
    static func toArray(string: String) -> [UafProtocolRequest] {
        if let data = string.data(using: .utf8) {
            do {
                return try JSONDecoder().decode([UafProtocolRequest].self, from: data)
            } catch let error {
                debugPrint("Deserialization of UafProtocolRequest failed: \(error)")
            }
        }
        return []
    }
}

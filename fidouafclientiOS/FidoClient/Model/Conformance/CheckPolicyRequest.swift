import Foundation

struct CheckPolicyRequest: Codable {
    let header: OperationHeader
    let policy: Policy
}

extension CheckPolicyRequest {
    
    static func toObject(string: String) -> [CheckPolicyRequest] {
        if let data = string.data(using: .utf8) {
            do {
                return try JSONDecoder().decode([CheckPolicyRequest].self, from: data)
            } catch {
                debugPrint("Deserialization of CheckPolicyRequest failed: \(error)")
            }
        }
        return []
    }
}

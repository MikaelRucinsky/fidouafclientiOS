import Foundation

struct AuthenticationResponse: Codable {

    let header: OperationHeader
    let fcParams: String
    let assertions: [AuthenticatorSignAssertion]
}

extension AuthenticationResponse {

    func toString() -> String? {
        do {
            let data = try JSONEncoder().encode(self)
            return String(data: data, encoding: .utf8)?.replacingOccurrences(of: "\\/", with: "/")
        } catch let error {
            debugPrint("Serialization of AuthenticationResponse failed \(error)")
        }
        return nil
    }
    
    func toArrayString() -> String? {
        do {
            let data = try JSONEncoder().encode([self])
            return String(data: data, encoding: .utf8)?.replacingOccurrences(of: "\\/", with: "/")
        } catch let error {
            debugPrint("Serialization of AuthenticationResponse failed: \(error)")
        }
        return nil
    }
}

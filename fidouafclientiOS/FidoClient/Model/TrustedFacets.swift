import Foundation

struct TrustedFacets: Codable {

    let version: Version
    let ids: [String]
}

extension TrustedFacets {

    static func getArrayFromString(string: String) -> [TrustedFacets] {
        if let data = string.data(using: .utf8) {
            return getArrayFromData(data: data)
        }
        return []
    }
    
    static func getArrayFromData(data: Data) -> [TrustedFacets] {
        do {
            return try JSONDecoder().decode([TrustedFacets].self, from: data)
        } catch let error {
            debugPrint("Deserialization of TrustedFacets failed: \(error)")
        }
        return []
    }
}

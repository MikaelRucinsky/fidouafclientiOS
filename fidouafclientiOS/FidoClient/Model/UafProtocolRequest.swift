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
    
    static func validate(requests: [UafProtocolRequest]) -> Bool {
        // find version duplicates
        let grouped = Dictionary(grouping: requests, by: { ($0.header.upv) })
        let filtered = grouped.values.filter { $0.count > 1 }
        
        guard filtered.count <= 0 else { return false }
        
        // find requests which serverData length is larger than 1536 characters
        let serverDataFiltered = requests.filter { $0.header.serverData?.count ?? 0 > 1536 || $0.header.serverData?.count ?? 1 <= 0 }
        guard serverDataFiltered.isEmpty else { return false }
        
        // find unknown extensions with fail_if_unknown == true
        let failIfUnknownExtensions = requests.compactMap { $0.header.exts }.flatMap { $0 }.filter { $0.fail_if_unknown }
        let unknownExtensions = failIfUnknownExtensions.filter { AuthenticatorMetadata.authenticator.supportedExtensionIDs.contains($0.id) }
        guard unknownExtensions.isEmpty else { return false }
        
        // find extensionIds which are longer than 32 characters
        let longOrShortExtIds = requests.compactMap { $0.header.exts }.flatMap { $0 }.filter { $0.id.count > 32 || $0.id.count <= 0 }
        guard longOrShortExtIds.isEmpty else { return false }
        
        return true
    }
    
    static func validateVersion(requests: [UafProtocolRequest]) -> Bool {
        // find unsupported versions
        let versionResult = requests.map { $0.header.upv }.map { AuthenticatorMetadata.supportedVersions.contains($0) }
        
        guard !versionResult.contains(false) else { return false }
        
        return true
    }
}

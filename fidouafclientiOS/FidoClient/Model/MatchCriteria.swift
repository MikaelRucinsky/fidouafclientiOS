import Foundation

struct MatchCriteria: Codable {

    let aaid: [String]
    let vendorID: [String]
    let keyIDs: [String]
    let userVerification: Int?
    let keyProtection: Int?
    let matcherProtection: Int?
    let attachmentHint: Int?
    let tcDisplay: Int?
    let authenticationAlgorithms: [Int]
    let assertionSchemes: [String]
    let attestationTypes: [Int]
    let authenticatorVersion: Int?
    let exts: [Extension]
}

extension MatchCriteria {
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        
        aaid = (try? values.decode([String].self, forKey: .aaid)) ?? []
        vendorID = (try? values.decode([String].self, forKey: .vendorID)) ?? []
        keyIDs = (try? values.decode([String].self, forKey: .keyIDs)) ?? []
        userVerification = try? values.decode(Int.self, forKey: .userVerification)
        keyProtection = try? values.decode(Int.self, forKey: .keyProtection)
        matcherProtection = try? values.decode(Int.self, forKey: .matcherProtection)
        attachmentHint = try? values.decode(Int.self, forKey: .attachmentHint)
        tcDisplay = try? values.decode(Int.self, forKey: .tcDisplay)
        authenticationAlgorithms = (try? values.decode([Int].self, forKey: .authenticationAlgorithms)) ?? []
        assertionSchemes = (try? values.decode([String].self, forKey: .assertionSchemes)) ?? []
        attestationTypes = (try? values.decode([Int].self, forKey: .attestationTypes)) ?? []
        authenticatorVersion = try? values.decode(Int.self, forKey: .authenticatorVersion)
        exts = (try? values.decode([Extension].self, forKey: .exts)) ?? []
    }
}

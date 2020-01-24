import Foundation

struct Policy: Codable {

    let accepted: [[MatchCriteria]]
    let disallowed: [MatchCriteria]?
}

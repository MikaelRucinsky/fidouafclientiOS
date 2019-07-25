import Foundation

struct OperationHeader: Codable {

    let upv: Version
    let op: Operation
    let appID: String
    let serverData: String
    let exts: [Extension]
}

extension OperationHeader {
    
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        upv = try values.decode(Version.self, forKey: .upv)
        op = try values.decode(Operation.self, forKey: .op)
        appID = try values.decode(String.self, forKey: .appID)
        serverData = (try? values.decode(String.self, forKey: .serverData)) ?? ""
        exts = (try? values.decode([Extension].self, forKey: .exts)) ?? []
    }
}

import Foundation

public struct ChannelBinding: Codable {

    let serverEndPoint: String?
    let tlsServerCertificate: String?
    let tlsUnique: String?
    let cid_pubKey: String?
}

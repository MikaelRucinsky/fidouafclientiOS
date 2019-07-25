import Foundation

public struct ChannelBinding: Codable {

    public let serverEndPoint: String?
    public let tlsServerCertificate: String?
    public let tlsUnique: String?
    public let cid_pubKey: String?
}

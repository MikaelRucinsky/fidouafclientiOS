import Foundation

public struct ChannelBinding: Codable {

    public let serverEndPoint: String?
    public let tlsServerCertificate: String?
    public let tlsUnique: String?
    public let cid_pubKey: String?
    
    public init(serverEndPoint: String?, tlsServerCertificate: String?, tlsUnique: String?, cid_pubKey: String?) {
        self.serverEndPoint = serverEndPoint
        self.tlsServerCertificate = tlsServerCertificate
        self.tlsUnique = tlsUnique
        self.cid_pubKey = cid_pubKey
    }
}

import Foundation

public struct UAFMessage: Codable {
    public let uafProtocolMessage: String
    
    public init (uafProtocolMessage: String) {
        self.uafProtocolMessage = uafProtocolMessage
    }
}

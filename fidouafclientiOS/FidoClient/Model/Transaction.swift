import Foundation

struct Transaction: Codable {

    let contentType: String
    let content: String
    let tcDisplayPNGCharacteristics: DisplayPNGCharacteristicsDescriptor?
}

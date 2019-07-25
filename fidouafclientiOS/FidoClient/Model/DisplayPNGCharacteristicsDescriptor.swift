import Foundation

struct DisplayPNGCharacteristicsDescriptor: Codable {

    let width: Int
    let height: Int
    let bitDepth: String
    let colorType: String
    let compression: String
    let filter: String
    let interlace: String
    let plte: [RgbPalletteEntry]
}

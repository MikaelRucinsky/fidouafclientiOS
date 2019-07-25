import Foundation

class UnsignedUtil {
    
    static func encodeInt(int: Int) -> Data {
        return Data(bytes: [UInt8(int & 0xff), UInt8(int >> 8 & 0xff)])
    }
    
    static func encodeInt32(int: UInt) -> Data {
        return Data(bytes: [
                UInt8(int & 0x000000ff),
                UInt8((int & 0x0000ff00) >> 8),
                UInt8((int & 0x00ff0000) >> 16),
                UInt8((int & 0xff000000) >> 24)
        ])
    }
}

import Foundation

extension String {
    
    func base64UrlWithoutPaddingDecoded() -> String? {
        var base64String = self.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let paddingCount = base64String.count % 4
        if (paddingCount > 0) {
            for _ in 0..<paddingCount {
                base64String.append("=")
            }
        }
        if let data = Data(base64Encoded: base64String) {
            return String(data: data, encoding: .utf8)
        }
        return nil
    }
    
    func base64UrlWithoutPaddingDecoded() -> Data? {
        var base64String = self.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let paddingCount = base64String.count % 4
        if (paddingCount > 0) {
            for _ in 0..<paddingCount {
                base64String.append("=")
            }
        }
        if let data = Data(base64Encoded: base64String) {
            return data
        }
        return nil
    }
}

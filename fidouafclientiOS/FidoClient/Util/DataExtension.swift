import Foundation

extension Data {
    
    func base64UrlEncodedString(removeBackslash: Bool) -> String {
        var data = self
        
        if (removeBackslash) {
            for item in 0..<data.count {
                if(item < data.count) {
                    if (data[item] == 92) {
                        data.remove(at: item)
                    }
                }
            }
        }
        
        return data.base64EncodedString(options: .init(rawValue: 0))
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
    
    func base64UrlWithoutPaddingEncodedString(removeBackslash: Bool) -> String {
        return base64UrlEncodedString(removeBackslash: removeBackslash)
            .replacingOccurrences(of: "=", with: "")
    }
}

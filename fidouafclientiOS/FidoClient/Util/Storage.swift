import Foundation

class Storage {

    private static var keyIds: [String] = []
    
    private static let DocumentsDirectory = FileManager().urls(for: .documentDirectory, in: .userDomainMask).first!
    static let ArchiveURL = Storage.DocumentsDirectory.appendingPathComponent("FidoClient").appendingPathComponent("keyIds")
    
//    static let dict = ["username": "keyId"]
    
    static func hasKeyId(appId: String, keyId: String) -> Bool {
        if let userKeyIdDict = load(appId: appId) {
            return userKeyIdDict.values.contains(keyId)
        } else {
            return false
        }
    }
    
    /**
         Stores usernames and keyIds for an appId
        -dict ["username", "keyId"]
     */
//    static func storeDict(appId: String, dict: [String: String]) {
//        UserDefaults.init(suiteName: "FIDOClient")?.set(dict, forKey: appId)
//    }
    
    /**
        Returns usernames and keyIds for an appId
     */
//    static func getDict(appId: String) -> [String: String]? {
//        return UserDefaults.init(suiteName: "FIDOClient")?.dictionary(forKey: appId) as? [String : String]
//    }
    
    static func store(appId: String, dict: [String: String]) {
        do {
            if (!FileManager.default.fileExists(atPath: ArchiveURL.path)) {
                try FileManager.default.createDirectory(at: ArchiveURL, withIntermediateDirectories: true, attributes: nil)
            }
            
            let url = ArchiveURL.appendingPathComponent(Hash.sha256(data: appId.data(using: .utf8)!).base64UrlWithoutPaddingEncodedString(removeBackslash: false))
            if #available(iOS 11.0, *) {
                let archive = try NSKeyedArchiver.archivedData(withRootObject: dict, requiringSecureCoding: true)
                try archive.write(to: url)
            } else {
                let isSuccessfulSave = NSKeyedArchiver.archiveRootObject(dict, toFile: url.path)
                if !isSuccessfulSave {
                    print("Failed to save keyIds...")
                }
            }
        } catch {
            print("Error saving keyId file: \(error)")
        }
    }
    
    static func load(appId: String) -> [String: String]? {
        let url = ArchiveURL.appendingPathComponent(Hash.sha256(data: appId.data(using: .utf8)!).base64UrlWithoutPaddingEncodedString(removeBackslash: false))
        guard let archiveData = try? Data(contentsOf: url) else { return nil }
        guard let keyIds = try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(archiveData) as? [String: String] else { return nil }
        return keyIds
        
        
//        return NSKeyedUnarchiver.unarchiveObject(withFile: ArchiveURL.appendingPathComponent(Hash.sha256(data: appId.data(using: .utf8)!).base64UrlWithoutPaddingEncodedString(removeBackslash: false)).path) as? [String: String]
//
//        NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(<#T##data: Data##Data#>)
    }
}

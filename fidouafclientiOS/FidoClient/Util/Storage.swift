import Foundation

class Storage {

    private static var keyIds: [String] = []

    static func storeKeyId(appId: String, keyId: String) {
        let _ = getKeyIds(appId: appId)
        keyIds.append(keyId)
        UserDefaults.standard.set(keyIds, forKey: appId)
    }
    
    static func getKeyIds(appId: String) -> [String] {
        if let keyIds = UserDefaults.standard.value(forKey: appId) {
            self.keyIds = keyIds as! [String]
        } else {
            self.keyIds = []
        }
        return self.keyIds
    }
    
    static func hasKeyId(appId: String, keyId: String) -> Bool {
        let keyIds = getKeyIds(appId: appId)
        return keyIds.contains(keyId)
    }
}

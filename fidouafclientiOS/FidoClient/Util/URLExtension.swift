import Foundation

extension URL {
    func extractXCallbackUrlData() throws -> XCallbackUrlData? {
        let path = self.path.dropFirst()
        let uafType = UafType(rawValue: String(path))
        guard self.scheme == "FidoUAFClient1" else { return nil }
        guard self.host == "x-callback-url" else { return nil }
        guard uafType == UafType.CHECK_POLICY || uafType == UafType.DISCOVER || uafType == UafType.UAF_OPERATION || uafType == UafType.UAF_OPERATION_COMPLETION_STATUS else { return nil }
        
        let xSuccess = self.valueOfQuery("x-success")
        let state = self.valueOfQuery("state")
        let secretKey = self.valueOfQuery("key")
        let json = self.valueOfQuery("json")
        
        guard xSuccess != nil else { return nil }
        guard secretKey != nil else { return nil }
        
        return XCallbackUrlData(requestType: uafType!, xSuccessUrl: xSuccess!, secretKey: secretKey!, state: state, json: json)
    }
    
    func valueOfQuery(_ queryParamName: String) -> String? {
        guard let url = URLComponents(url: self, resolvingAgainstBaseURL: true) else { return nil }
        return url.queryItems?.first(where: { $0.name == queryParamName })?.value
    }
}



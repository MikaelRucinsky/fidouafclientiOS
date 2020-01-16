import Foundation

// MARK: XCallbackUrlData

public struct XCallbackUrlData {
    let requestType: UafType
    let xSuccessUrl: String
    let secretKey: String // base64url-encoded
    let state: String?
    let json: String? // base64url-encoded
}


// MARK: XCallbackUrlResponseData
public protocol XCallbackUrlResponseData: Codable {
    var errorCode: CShort { get }
}

public struct XCallbackUrlDiscoveryResultData: XCallbackUrlResponseData {
    public var errorCode: CShort
    let discoveryData: String?
}

public struct XCallbackUrlCheckPolicyResultData: XCallbackUrlResponseData {
    public var errorCode: CShort
}

public struct XCallbackUrlUafOperationResultData: XCallbackUrlResponseData {
    public var errorCode: CShort
    let message: String?
}


// MARK: XCallbackUrlRequestData

public protocol XCallbackUrlRequestData: Codable {
    
}

public struct XCallbackUrlDiscoveryRequestData: XCallbackUrlRequestData {
    
}

public struct XCallbackUrlCheckPolicyRequestData: XCallbackUrlRequestData {
    let message: String
    let origin: String?
}

public struct XCallbackUafOperationRequestData: XCallbackUrlRequestData {
    let message: String
    let origin: String?
    let channelBindings: String
}

public struct XCallbackUrlUafOperationCompletionStatusRequestData: XCallbackUrlRequestData {
    let message: String
    let responseCode: CShort
}

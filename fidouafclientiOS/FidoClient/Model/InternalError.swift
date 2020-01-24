import Foundation

enum InternalError: Error {
    case Default(String)
    case FIDO_User_Cancelled
    case FIDO_Unsupported_Version
    case FIDO_No_Suitable_Authenticator
    case FIDO_Protocol_Error
    case FIDO_Untrusted_Facet_Id
    case FIDO_Key_Disappeared_Permanently
    case FIDO_Unknown
}

import Foundation

public enum FidoError: CShort {
    case NO_ERROR = 0x00
    case WAIT_USER_INTERACTION = 0x01
    case INSECURE_TRANSPORT = 0x02
    case USER_CANCELLED = 0x03
    case UNSUPPORTED_VERSION = 0x04
    case NO_SUITABLE_AUTHENTICATOR = 0x05
    case PROTOCOL_ERROR = 0x06
    case UNTRUSTED_FACET_ID = 0x07
    case KEY_DISAPPEARED_PERMANENTLY = 0x09
    case UNKNOWN = 0xFF
}

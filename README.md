# FIDO UAF Client & Authenticator

FIDO UAF Client & Authenticator for iOS by Hanko.

**Supported UAF versions:** 1.0

## Installation

### Carthage

To integrate FidoUafClientiOS into your Xcode project using Carthage, specify it in your Cartfile:

```
github "teamhanko/fidouafclientiOS" == 0.0.5
```

## Configuration

FidoUafClientiOS uses FaceID, so you have to define `NSFaceIDUsageDescription` in your `Info.plist`.

### OperationPrompts

The FidoUafClientiOS displays 
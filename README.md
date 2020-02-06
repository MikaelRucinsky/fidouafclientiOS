# FIDO UAF Client & Authenticator

FIDO UAF Client & Authenticator Combo for iOS by Hanko.

**Supported UAF versions:** `[1.1]`

## Breaking Changes

### 0.x.x -> 1.x.x

From 1.0.0 the keyIds are generated and stored in a different, not backwards compatible way. So all before generated keys are not known by the authenticator and can not be used anymore.

## Installation

### Carthage

To integrate FidoUafClientiOS into your Xcode project using Carthage, specify it in your Cartfile:

```
github "teamhanko/fidouafclientiOS" == 1.0.0
```

### CocoaPods

To integrate FidoUafClientiOS into your Xcode project using CocoaPods, specify it in your Podfile:

```
pod 'FidoUafClientiOS', '1.0.0'
```

## Configuration

FidoUafClientiOS uses FaceID, so you must define `NSFaceIDUsageDescription` in your `Info.plist`.

### OperationPrompts

The FidoUafClientiOS uses default values to display `kSecUseOperationPrompt` when using the private keys.
The default values are localized to English and German.
To override the default values just add the keys `biomentryOperationPromptReg` and `biomentryOperationPromptAuth` to your projects `Localizable.strings`.

> **Note:** If a request contains a transaction the `biomentryOperationPromptAuth` will be overriden with the transaction content.

## Basic Usage

```swift
let uafMessage = UAFMessage(uafProtocolMessage: "<fido-uaf-request>")
FidoClient.process(uafMessage: uafMessage) { resultMessage, error in 
	// send resultMessage to your Fido-Server
}
```

## License

	Copyright 2020 Hanko

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

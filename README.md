# FIDO UAF Client & Authenticator

FIDO UAF Client & Authenticator for iOS by Hanko.

**Supported UAF versions:** 1.0

## Installation

### Carthage

To integrate FidoUafClientiOS into your Xcode project using Carthage, specify it in your Cartfile:

```
github "teamhanko/fidouafclientiOS" == 0.1.6
```

## Configuration

FidoUafClientiOS uses FaceID, so you must define `NSFaceIDUsageDescription` in your `Info.plist`.

### OperationPrompts

The FidoUafClientiOS uses default values to display `kSecUseOperationPrompt` when using the private keys.
To override the default values just add the keys `biomentryOperationPromptReg` and `biomentryOperationPromptAuth` to your projects `Localizable.strings`.

> **Note:** If a request contains a transaction the `biomentryOperationPromptAuth` will be overriden with the transaction content.

## Basic Usage

```swift
let uafMessage = UAFMessage(uafProtocolMessage: "<fido-uaf-request>")
let response = try FidoClient.process(uafMessage: uafMessage)
if let uafResponse = response?.uafProtocolMessage {
    // verify uafResponse
}
```

# License

	Copyright 2019 Hanko

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

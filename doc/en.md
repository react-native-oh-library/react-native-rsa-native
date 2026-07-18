> Template version: v0.3.0

<p align="center">
  <h1 align="center"> <code>react-native-rsa-native</code> </h1>
</p>

This project is based on [react-native-rsa-native@2.0.5](https://github.com/amitaymolko/react-native-rsa-native/tree/master).

## 1. Installation and Usage

Please refer to the Releases page of the third-party library for the corresponding version information

| Third-party Library Version | Release Information       | Supported RN Version |
| ---------- | ------------------------------------------------------------ | ---------- |
| 2.0.6 | [@react-native-ohos/react-native-rsa-native Releases](https://github.com/react-native-oh-library/react-native-rsa-native/releases) | 0.72/0.77       |

For older versions not published on npm, please refer to the [Installation Guide](/en/tgz-usage-en.md) to install the tgz package.

Go to the project directory and execute the following instruction:

<!-- tabs:start -->

#### **npm**

```bash
npm install @react-native-ohos/react-native-rsa-native
```

#### **yarn**

```bash
yarn add @react-native-ohos/react-native-rsa-native
```

<!-- tabs:end -->

The following code shows the basic use scenario of the repository:

> [!WARNING] The name of the imported repository remains unchanged.

```js
import React, { useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, ScrollView } from 'react-native';
import { RSA, RSAKeychain } from 'react-native-rsa-native';

const RSADemo = () => {
  const [result, setResult] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const runAllTests = async () => {
    setIsLoading(true);
    try {
      let testResult = '';
      const testText = 'Hello World 123';
      const keyTag = 'com.example.testkey';

      testResult += 'RSA:\n';
      const rsaKeys = await RSA.generate();
      const encrypted = await RSA.encrypt(testText, rsaKeys.public);
      const decrypted = await RSA.decrypt(encrypted, rsaKeys.private);
      const rsaMatch = decrypted === testText;
      
      testResult += `Decrypt content: ${decrypted}\n`;
      testResult += `Verification result: ${rsaMatch ? 'correct' : 'error'}\n\n`;

      const rsaSignature = await RSA.sign(testText, rsaKeys.private);
      const rsaValid = await RSA.verify(rsaSignature, testText, rsaKeys.public);
      testResult += `RSA signature verification: ${rsaValid ? 'correct' : 'error'}\n\n`;

      testResult += 'RSAKeychain:\n';
      await RSAKeychain.generate(keyTag);
      const keychainEncrypted = await RSAKeychain.encrypt(testText, keyTag);
      const keychainDecrypted = await RSAKeychain.decrypt(keychainEncrypted, keyTag);
      const keychainMatch = keychainDecrypted === testText;
      
      testResult += `Decrypt content: ${keychainDecrypted}\n`;
      testResult += `Verification result: ${keychainMatch ? 'correct' : 'error'}\n\n`;

      const keychainSignature = await RSAKeychain.sign(testText, keyTag);
      const keychainValid = await RSAKeychain.verify(keychainSignature, testText, keyTag);
      testResult += `Hardware signature verification: ${keychainValid ? 'correct' : 'error'}\n`;

      await RSAKeychain.deletePrivateKey(keyTag);
      
      setResult(testResult);
    } catch (error) {
      setResult(`failed: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <ScrollView style={styles.container}>
      <Text style={styles.title}>react-native-rsa-native</Text>
      <TouchableOpacity 
        style={[styles.button, isLoading && styles.buttonDisabled]} 
        onPress={runAllTests}
        disabled={isLoading}
      >
        <Text style={styles.buttonText}>
          {isLoading ? 'testing...' : 'Click to test'}
        </Text>
      </TouchableOpacity>
      <Text style={styles.resultTitle}>result:</Text>
      <View style={styles.resultBox}>
        <Text style={styles.resultText}>{result || 'Click the button to start testing'}</Text>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#f5f5f5',
  },
  title: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
    color: '#333',
  },
  button: {
    backgroundColor: '#2196F3',
    padding: 16,
    borderRadius: 8,
    alignItems: 'center',
    marginBottom: 16,
  },
  buttonDisabled: {
    backgroundColor: '#999',
    opacity: 0.6,
  },
  buttonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: '600',
  },
  resultTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#555',
  },
  resultBox: {
    backgroundColor: 'white',
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    padding: 15,
    minHeight: 300,
  },
  resultText: {
    fontSize: 14,
    lineHeight: 22,
    color: '#333',
  },
});

export default RSADemo;

```
## 2. Link

This step provides guidance for manually configuring native dependencies.

Open the `harmony` directory of the HarmonyOS project in DevEco Studio.

### 1. Adding the overrides Field to oh-package.json5 File in the Root Directory of the Project

```json
{
  ...
  "overrides": {
    "@rnoh/react-native-openharmony" : "./react_native_openharmony"
  }
}
```

### 2. Introducing Native Code

Currently, two methods are available:

Method 1 (recommended): Use the HAR file.

> [!TIP] The HAR file is stored in the `harmony` directory in the installation path of the third-party library.

Open `entry/oh-package.json5` file and add the following dependencies:

```json
"dependencies": {
    "@rnoh/react-native-openharmony": "file:../react_native_openharmony",
    "@react-native-ohos/react-native-rsa-native": "file:../../node_modules/@react-native-ohos/react-native-rsa-native/harmony/rn_rsa_native.har"
  }
```

Click the `sync` button in the upper right corner.

Alternatively, run the following instruction on the terminal:

```bash
cd entry
ohpm install
```

Method 2: Directly link to the source code.

> [!TIP] For details, see [Directly Linking Source Code](/en/link-source-code.md).

### 3. Configuring CMakeLists and Introducing RTNRsaNativePackage

Open `entry/src/main/cpp/CMakeLists.txt` and add the following code:

```diff
project(rnapp)
cmake_minimum_required(VERSION 3.4.1)
set(CMAKE_SKIP_BUILD_RPATH TRUE)
set(RNOH_APP_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(NODE_MODULES "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../node_modules")
+ set(OH_MODULES "${CMAKE_CURRENT_SOURCE_DIR}/../../../oh_modules")
set(RNOH_CPP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../react-native-harmony/harmony/cpp")
set(LOG_VERBOSITY_LEVEL 1)
set(CMAKE_ASM_FLAGS "-Wno-error=unused-command-line-argument -Qunused-arguments")
set(CMAKE_CXX_FLAGS "-fstack-protector-strong -Wl,-z,relro,-z,now,-z,noexecstack -s -fPIE -pie")
set(WITH_HITRACE_SYSTRACE 1) # for other CMakeLists.txt files to use
add_compile_definitions(WITH_HITRACE_SYSTRACE)

add_subdirectory("${RNOH_CPP_DIR}" ./rn)

# RNOH_BEGIN: manual_package_linking_1
add_subdirectory("../../../../sample_package/src/main/cpp" ./sample-package)
+ add_subdirectory("${OH_MODULES}/@react-native-ohos/react-native-rsa-native/src/main/cpp" ./rn_rsa_native)
# RNOH_END: manual_package_linking_1

file(GLOB GENERATED_CPP_FILES "./generated/*.cpp")

add_library(rnoh_app SHARED
    ${GENERATED_CPP_FILES}
    "./PackageProvider.cpp"
    "${RNOH_CPP_DIR}/RNOHAppNapiBridge.cpp"
)
target_link_libraries(rnoh_app PUBLIC rnoh)

# RNOH_BEGIN: manual_package_linking_2
target_link_libraries(rnoh_app PUBLIC rnoh_sample_package)
+ target_link_libraries(rnoh_app PUBLIC rnoh_rsa_native)
# RNOH_END: manual_package_linking_2
```

Open `entry/src/main/cpp/PackageProvider.cpp` and add the following code:

```diff
#include "RNOH/PackageProvider.h"
#include "generated/RNOHGeneratedPackage.h"
#include "SamplePackage.h"
+ #include "RTNRsaNativePackage.h"

using namespace rnoh;

std::vector<std::shared_ptr<Package>> PackageProvider::getPackages(Package::Context ctx) {
    return {
        std::make_shared<RNOHGeneratedPackage>(ctx),
        std::make_shared<SamplePackage>(ctx),
+       std::make_shared<RTNRsaNativePackage>(ctx),
    };
}
```

### 4. Introduce the RNRSA Package component on the ArkTs side

Open the `entry/src/main/ets/RNPackagesFactory.ts` file and add the following code:

```diff
...
+ import { RNRSAPackage } from '@react-native-ohos/react-native-rsa-native/ts';

export function createRNPackages(ctx: RNPackageContext): RNPackage[] {
  return [
    new SamplePackage(ctx),
+   new RNRSAPackage(ctx)
  ];
}

```

### 5. Running

Click the `sync` button in the upper right corner.

Alternatively, run the following instruction on the terminal:

```bash
cd entry
ohpm install
```

Then build and run the code.

## 3. Constraints

### 3.1 Compatibility

To use this repository, you need to use the correct React-Native and RNOH versions. In addition, you need to use DevEco Studio and the ROM on your phone.

> [!TIP] Versions >=2.0.6 need to run on DevEco Studio 5.1.0(API18) or later.

Verified in the following versions.

1. RNOH: 0.72.33; SDK：OpenHarmony 5.0.0.71(API Version 12 Release); IDE：DevEco Studio 5.0.3.900; ROM：NEXT.0.0.71;
2. RNOH: 0.77.18; SDK: HarmonyOS 6.0.0 Release SDK; IDE: DevEco Studio 6.0.0.858; ROM: 6.0.0.112;

## 4. API

> [!TIP] The **Platform** column indicates the platform where the properties are supported in the original third-party library.

> [!TIP] If the value of **HarmonyOS Support** is **yes**, it means that the HarmonyOS platform supports this property; **no** means the opposite; **partially** means some capabilities of this property are supported. The usage method is the same on different platforms and the effect is the same as that of iOS or Android.

**RSA**

| Name | Description | Required | Platform | HarmonyOS Support  |
| ---- | ----------- | -------- | -------- | ------------------ |
| generate  | Generate default key     | no | all      | yes |
| generateKeys  | Generate a specified size key     | no | all      | yes |
| encrypt  | String encryption     | no | all     | no |
| encrypt64  | Base64 data encryption    | no | all      | yes |
| decrypt  | String decryption    | no | all      | no |
| decrypt64  | Base64 data decryption    | no | all      | yes |
| sign  | String signature     | no | all      | yes |
| signWithAlgorithm  | Specify algorithm signature     | no | all      | yes |
| sign64  | Base64 data signature     | no | all      | yes |
| sign64WithAlgorithm  | Specify algorithm Base64 signature     | no | all      | yes |
| verify  | Signature verification          | no | all      | yes |
| verifyWithAlgorithm  | Specify algorithm validation     | no | all      | yes |
| verify64  | Base64 signature verification     | no | all      | yes |
| verify64WithAlgorithm  | Specify algorithm Base64 validation     | no | all      | yes |

**RSAKeychain**

| Name | Description | Required | Platform | HarmonyOS Support  |
| ---- | ----------- | -------- | -------- | ------------------ |
| generate  | Generate default hardware key     | no | all      | yes |
| generateKeys  | Generate hardware keys of specified size     | no | all      | yes |
| generateEC  | Specify the generation of EC hardware key     | no | iOS      | yes |
| generateCSR  | Generate certificate signature request     | no | all      | yes |
| deletePrivateKey  | Delete hardware private key     | no | all     | yes |
| encrypt  | Hardware string encryption    | no | all      | yes |
| encrypt64  | Hardware Base64 data encryption    | no | all      | yes |
| decrypt  | Hardware string decryption     | no | all      | yes |
| decrypt64  | Hardware Base64 data decryption    | no | all      | yes |
| sign  | Hardware string signature          | no | all      | yes |
| signWithAlgorithm  | Hardware specified algorithm signature          | no | all      | yes |
| sign64WithAlgorithm  | Hardware Base64 specifies algorithm signature          | no | all      | yes |
| verify  | Hardware signature verification          | no | all      | yes |
| verifyWithAlgorithm  | Hardware specified algorithm validation          | no | all      | yes |
| verify64WithAlgorithm  | Hardware specified algorithm Base64 verification          | no | all      | yes |
| getPublicKey  | Get public key          | no | all      | yes |
| getPublicKeyDER  | Obtain DER format public key          | no | all      | yes |
| getPublicKeyRSA  | Obtain RSA format public key          | no | all      | yes |

## 5. Others

## 6. License

This project is licensed under [The MIT License (MIT)](https://github.com/amitaymolko/react-native-rsa-native/blob/master/LICENSE).


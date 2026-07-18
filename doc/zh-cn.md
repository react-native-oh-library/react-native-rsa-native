> 模板版本：v0.3.0

<p align="center">
  <h1 align="center"> <code>react-native-rsa-native</code> </h1>
</p>

本项目基于 [react-native-rsa-native@2.0.5](https://github.com/amitaymolko/react-native-rsa-native/tree/master) 开发。

## 1. 安装与使用

请到三方库的 Releases 发布地址查看配套的版本信息：

| 三方库版本 | 发布信息                                                     | 支持RN版本 | 
| ---------- | ------------------------------------------------------------ | ---------- |
| 2.0.6 | [@react-native-ohos/react-native-rsa-native Releases](https://github.com/react-native-oh-library/react-native-rsa-native/releases) | 0.72/0.77       |

对于未发布到npm的旧版本，请参考[安装指南](/zh-cn/tgz-usage.md)安装tgz包。

进入到工程目录并输入以下命令：

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

下面的代码展示了这个库的基本使用场景：

> [!WARNING] 使用时 import 的库名不变。

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

此步骤为手动配置原生依赖项的指导。

首先需要使用 DevEco Studio 打开项目里的 HarmonyOS 工程 `harmony`

### 1.在工程根目录的 `oh-package.json5` 添加 overrides 字段

```json
{
  ...
  "overrides": {
    "@rnoh/react-native-openharmony" : "./react_native_openharmony"
  }
}
```

### 2.引入原生端代码

目前有两种方法：

1. 通过 har 包引入（在 IDE 完善相关功能后该方法会被遗弃，目前首选此方法）；
2. 直接链接源码。

方法一：通过 har 包引入（推荐）

> [!TIP] har 包位于三方库安装路径的 `harmony` 文件夹下。

打开 `entry/oh-package.json5`，添加以下依赖

```json
"dependencies": {
    "@rnoh/react-native-openharmony": "file:../react_native_openharmony",
    "@react-native-ohos/react-native-rsa-native": "file:../../node_modules/@react-native-ohos/react-native-rsa-native/harmony/rn_rsa_native.har"
  }
```

点击右上角的 `sync` 按钮

或者在终端执行：

```bash
cd entry
ohpm install
```

方法二：直接链接源码

> [!TIP] 如需使用直接链接源码，请参考[直接链接源码说明](/zh-cn/link-source-code.md)

### 3.配置 CMakeLists 和引入 RTNRsaNativePackage

打开 `entry/src/main/cpp/CMakeLists.txt`，添加：

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

打开 `entry/src/main/cpp/PackageProvider.cpp`，添加：

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

### 4.在 ArkTs 侧引入 RNRSA Package

打开 `entry/src/main/ets/RNPackagesFactory.ts`，添加：

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

### 5.运行

点击右上角的 `sync` 按钮

或者在终端执行：

```bash
cd entry
ohpm install
```

然后编译、运行即可。

## 3. 约束与限制

### 3.1 兼容性

要使用此库，需要使用正确的 React-Native 和 RNOH 版本。另外，还需要使用配套的 DevEco Studio 和 手机 ROM。

> [!TIP] version>=2.0.6的版本需要在DevEco Studio 5.1.0(API18) 及以上版本编译

在以下版本验证通过：

1. RNOH: 0.72.33; SDK：OpenHarmony 5.0.0.71(API Version 12 Release); IDE：DevEco Studio 5.0.3.900; ROM：NEXT.0.0.71;
2. RNOH: 0.77.18; SDK: HarmonyOS 6.0.0 Release SDK; IDE: DevEco Studio 6.0.0.858; ROM: 6.0.0.112;

## 4. API

> [!TIP] "Platform"列表示该属性在原三方库上支持的平台。

> [!TIP] "HarmonyOS Support"列为 yes 表示 HarmonyOS 平台支持该属性；no 则表示不支持；partially 表示部分支持。使用方法跨平台一致，效果对标 iOS 或 Android 的效果。

**RSA**

 | Name | Description | Required | Platform | HarmonyOS Support  |
| ---- | ----------- | -------- | -------- | ------------------ |
| generate  | 生成默认密钥     | no | all      | yes |
| generateKeys  | 生成指定大小密钥     | no | all      | yes |
| encrypt  | 字符串加密     | no | all     | yes |
| encrypt64  | Base64数据加密    | no | all      | yes |
| decrypt  | 字符串解密    | no | all      | yes |
| decrypt64  | Base64数据解密    | no | all      | yes |
| sign  | 字符串签名     | no | all      | yes |
| signWithAlgorithm  | 指定算法签名     | no | all      | yes |
| sign64  | Base64数据签名     | no | all      | yes |
| sign64WithAlgorithm  | 指定算法Base64签名     | no | all      | yes |
| verify  | 签名验证          | no | all      | yes |
| verifyWithAlgorithm  | 指定算法验证     | no | all      | yes |
| verify64  | Base64签名验证     | no | all      | yes |
| verify64WithAlgorithm  | 指定算法Base64验证     | no | all      | yes |

**RSAKeychain**

| Name | Description | Required | Platform | HarmonyOS Support  |
| ---- | ----------- | -------- | -------- | ------------------ |
| generate  | 生成默认硬件密钥     | no | all      | yes |
| generateKeys  | 生成指定大小硬件密钥     | no | all      | yes |
| generateEC  | 生成EC硬件密钥     | no | iOS      | yes |
| generateCSR  | 生成证书签名请求     | no | all      | yes |
| deletePrivateKey  | 删除硬件私钥     | no | all     | yes |
| encrypt  | 硬件字符串加密    | no | all      | yes |
| encrypt64  | 硬件Base64数据加密    | no | all      | yes |
| decrypt  | 硬件字符串解密     | no | all      | yes |
| decrypt64  | 硬件Base64数据解密    | no | all      | yes |
| sign  | 硬件字符串签名          | no | all      | yes |
| signWithAlgorithm  | 硬件指定算法签名          | no | all      | yes |
| sign64WithAlgorithm  | 硬件Base64指定算法签名          | no | all      | yes |
| verify  | 硬件签名验证          | no | all      | yes |
| verifyWithAlgorithm  | 硬件指定算法验证          | no | all      | yes |
| verify64WithAlgorithm  | 硬件指定算法Base64验证          | no | all      | yes |
| getPublicKey  | 获取公钥          | no | all      | yes |
| getPublicKeyDER  | 获取DER格式公钥          | no | all      | yes |
| getPublicKeyRSA  | 获取RSA格式公钥          | no | all      | yes |

## 5. 其他

## 6. 开源协议

本项目基于 [The MIT License (MIT)](https://github.com/amitaymolko/react-native-rsa-native/blob/master/LICENSE) ，请自由地享受和参与开源。


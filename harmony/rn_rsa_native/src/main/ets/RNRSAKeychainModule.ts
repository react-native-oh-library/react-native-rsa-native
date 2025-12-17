import Logger from './Logger';
import { AnyThreadTurboModule, AnyThreadTurboModuleContext } from '@rnoh/react-native-openharmony/ts';
import { huks } from '@kit.UniversalKeystoreKit';
import { RSACommonUtils } from './RSACommonUtils';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { cert } from '@kit.DeviceCertificateKit';
import { deviceInfo } from '@kit.BasicServicesKit';

const TAG = '[RNRSAKeychain]';

export class RNRSAKeychainModule extends AnyThreadTurboModule {
  constructor(ctx: AnyThreadTurboModuleContext) {
    super(ctx);
    Logger.info(TAG, 'RNRSAKeychain module initialized');
  }

  async generate(keyTag: string): Promise<{ public: string }> {
    return await this.generateHuksSeparateKeys(keyTag, 2048, 'RSA');
  }

  async generateKeys(keyTag: string, keySize: number): Promise<{ public: string }> {
    if (![512, 768, 1024, 2048, 3072, 4096].includes(keySize)) {
      throw new Error(`Unsupported key size: ${keySize}.`);
    }
    return await this.generateHuksSeparateKeys(keyTag, keySize, 'RSA');
  }

  async generateEC(keyTag: string): Promise<{ public: string }> {
    return await this.generateHuksSeparateKeys(keyTag, 256, 'EC');
  }

  private async generateHuksSeparateKeys(
    keyTag: string,
    keySize: number,
    keyType: string
  ): Promise<{ public: string }> {
    const signKeyTag = `${keyTag}_sign`;
    if (keyType === 'EC') {
      await this.generateHUKSKey(signKeyTag, keySize,
        huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN |
        huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY,
        'EC'
      );
      const publicKey = await this.getRawECPublicKey(keyTag);
      return { public: publicKey };
    }
    else {
      const encryptKeyTag = `${keyTag}_encrypt`;
      const encryptPurposes = huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT |
      huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT;
      const signPurposes = huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN |
      huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY;

      await this.generateHUKSKey(encryptKeyTag, keySize, encryptPurposes, 'RSA');
      await this.generateHUKSKey(signKeyTag, keySize, signPurposes, 'RSA');
      const publicKey = await this.encodedPublicKeyDER(keyTag);
      return { public: publicKey };
    }
  }

  private getKeyTagForOperation(baseKeyTag: string, operation: 'encrypt' | 'decrypt' | 'sign' | 'verify'): string {
    if (operation === 'encrypt' || operation === 'decrypt') {
      return `${baseKeyTag}_encrypt`;
    } else {
      return `${baseKeyTag}_sign`;
    }
  }

  private async generateHUKSKey(alias: string, keySize: number, purposes: number,
    algorithmType: string): Promise<void> {
    const rsaKeySizeMap = {
      512: huks.HuksKeySize.HUKS_RSA_KEY_SIZE_512,
      768: huks.HuksKeySize.HUKS_RSA_KEY_SIZE_768,
      1024: huks.HuksKeySize.HUKS_RSA_KEY_SIZE_1024,
      2048: huks.HuksKeySize.HUKS_RSA_KEY_SIZE_2048,
      3072: huks.HuksKeySize.HUKS_RSA_KEY_SIZE_3072,
      4096: huks.HuksKeySize.HUKS_RSA_KEY_SIZE_4096,
      256: huks.HuksKeySize.HUKS_ECC_KEY_SIZE_256,
    };

    const hukKeySize = rsaKeySizeMap[keySize];
    if (!hukKeySize) {
      throw new Error(`unsupported: ${keySize}`);
    }
    const algorithm = algorithmType === 'EC' ? huks.HuksKeyAlg.HUKS_ALG_ECC : huks.HuksKeyAlg.HUKS_ALG_RSA;
    const properties: Array<huks.HuksParam> = [
      { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: algorithm },
      { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: hukKeySize },
      { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: purposes },
      { tag: huks.HuksTag.HUKS_TAG_PADDING, value: huks.HuksKeyPadding.HUKS_PADDING_PKCS1_V1_5 },
      {
        tag: huks.HuksTag.HUKS_TAG_KEY_STORAGE_FLAG,
        value: huks.HuksKeyStorageType.HUKS_STORAGE_KEY_EXPORT_ALLOWED
      },
      {
        tag: huks.HuksTag.HUKS_TAG_IS_KEY_ALIAS,
        value: true
      },
    ];

    const options: huks.HuksOptions = { properties };
    return new Promise<void>((resolve, reject) => {
      huks.isKeyItemExist(alias, options, (existError, existResult) => {
        if (existError) {
          Logger.error(TAG, `existError`);
        }
        if (existResult) {
          Logger.info(TAG, `existResult`);
          resolve();
          return;
        }
        huks.generateKeyItem(alias, options, (error: any) => {
          if (error) {
            Logger.error(TAG, `failed:`, error);
            reject(new Error(`failed: ${error.message || error}`));
          } else {
            Logger.info(TAG, `failed`);
            resolve();
          }
        });
      });
    });
  }

  async encrypt(data: string, keyTag: string): Promise<string> {
    try {
      const dataArray = RSACommonUtils.encodeToUtf8Bytes(data);
      const actualKeyTag = this.getKeyTagForOperation(keyTag, 'encrypt');
      const encryptedBytes = await this.performHuksEncrypt(actualKeyTag, dataArray);
      return RSACommonUtils.uint8ArrayToBase64WithLineBreaks(encryptedBytes);
    } catch (error) {
      Logger.error(TAG, `Encryption failed: ${error}`);
      throw error;
    }
  }

  private async performHuksEncrypt(keyTag: string, dataBytes: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const properties: Array<huks.HuksParam> = [
        { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_RSA },
        { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT },
        { tag: huks.HuksTag.HUKS_TAG_PADDING, value: huks.HuksKeyPadding.HUKS_PADDING_PKCS1_V1_5 },
        { tag: huks.HuksTag.HUKS_TAG_BLOCK_MODE, value: huks.HuksCipherMode.HUKS_MODE_ECB },
      ];

      const options: huks.HuksOptions = {
        properties,
        inData: dataBytes
      };

      huks.initSession(keyTag, options, (initError, initResult) => {
        if (initError) {
          reject(new Error('initSession failed'));
          return;
        }
        const handle = initResult.handle;
        huks.finishSession(handle, options, (finishError, finishResult) => {
          if (finishError) {
            Logger.error(`finishSession failed:`, JSON.stringify(finishError));
            this.abortHuksSession(handle);
            return;
          }

          const outData = finishResult.outData;
          if (!outData) {
            reject(new Error('The encryption result is empty'));
            return;
          }
          try {
            const encryptedBytes = RSACommonUtils.convertOutDataToUint8Array(outData);
            resolve(encryptedBytes);
          } catch (error) {
            reject(new Error(`failed: ${error}`));
          }
        });
      });
    });
  }

  private abortHuksSession(handle: number): void {
    const emptyOptions: huks.HuksOptions = { properties: [] };
    huks.abortSession(handle, emptyOptions, (abortError) => {
      if (abortError) {
        Logger.error(`abortSession failed:`, JSON.stringify(abortError));
      } else {
        Logger.info(`abortSession success`);
      }
    });
  }

  async decrypt(data: string, keyTag: string): Promise<string> {
    try {
      const encryptedBytes = RSACommonUtils.base64StringToUint8ArrayWithLineBreaks(data);
      const actualKeyTag = this.getKeyTagForOperation(keyTag, 'decrypt');
      const decryptedBytes = await this.performHuksDecrypt(actualKeyTag, encryptedBytes);
      return RSACommonUtils.decodeFromUtf8Bytes(decryptedBytes);
    } catch (error) {
      Logger.error(TAG, `Decryption failed: ${error}`);
      throw error;
    }
  }

  private async performHuksDecrypt(keyTag: string, encryptedBytes: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const properties: Array<huks.HuksParam> = [
        { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_RSA },
        { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT },
        { tag: huks.HuksTag.HUKS_TAG_PADDING, value: huks.HuksKeyPadding.HUKS_PADDING_PKCS1_V1_5 },
        { tag: huks.HuksTag.HUKS_TAG_BLOCK_MODE, value: huks.HuksCipherMode.HUKS_MODE_ECB },
      ];

      const options: huks.HuksOptions = {
        properties,
        inData: encryptedBytes
      };
      huks.initSession(keyTag, options, (initError, initResult) => {
        if (initError) {
          Logger.error(`initSession for decrypt failed:`, JSON.stringify(initError, null, 2));
          return;
        }
        const handle = initResult.handle;
        huks.finishSession(handle, options, (finishError, finishResult) => {
          if (finishError) {
            Logger.error(`finishSession for decrypt failed:`, JSON.stringify(finishError, null, 2));
            this.abortHuksSession(handle);
            return;
          }

          const outData = finishResult.outData;
          if (!outData) {
            reject(new Error('Decryption result is empty'));
            return;
          }
          try {
            const decryptedBytes = RSACommonUtils.convertOutDataToUint8Array(outData);
            resolve(decryptedBytes);
          } catch (error) {
            reject(new Error(`failed: ${error}`));
          }
        });
      });
    });
  }


  async sign(data: string, keyTag: string): Promise<string> {
    try {
      const keyType = await this.detectKeyType(keyTag);
      if (keyType === 'EC') {
        return await this.signWithAlgorithm(data, keyTag, 'SHA256withECDSA');
      } else {
        return await this.signWithAlgorithm(data, keyTag, 'SHA512withRSA');
      }
    } catch (error) {
      Logger.error(TAG, `Sign failed: ${error}`);
      throw new Error(error instanceof Error ? error.message : 'sign failed');
    }
  }

  async signWithAlgorithm(data: string, keyTag: string, algorithm?: string): Promise<string> {
    const actualAlgorithm = algorithm || 'SHA512withRSA';
    const actualKeyTag = this.getKeyTagForOperation(keyTag, 'sign');
    try {
      const dataBytes = RSACommonUtils.encodeToUtf8Bytes(data);
      const signatureBytes = await this.performHuksSignWithAlgorithm(actualKeyTag, dataBytes, actualAlgorithm);
      return RSACommonUtils.uint8ArrayToBase64(signatureBytes);
    } catch (error) {
      Logger.error(TAG, `Sign with algorithm failed: ${error}`);
      throw error;
    }
  }

  private async performHuksSignWithAlgorithm(keyTag: string, dataBytes: Uint8Array,
    algorithm: string): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      let digest = huks.HuksKeyDigest.HUKS_DIGEST_SHA256;

      if (algorithm.includes('SHA512')) {
        digest = huks.HuksKeyDigest.HUKS_DIGEST_SHA512;
      }

      const isEC = algorithm.includes('ECDSA');
      const huksAlg = isEC ? huks.HuksKeyAlg.HUKS_ALG_ECC : huks.HuksKeyAlg.HUKS_ALG_RSA;
      const padding = isEC ? huks.HuksKeyPadding.HUKS_PADDING_NONE : huks.HuksKeyPadding.HUKS_PADDING_PKCS1_V1_5;

      const properties: Array<huks.HuksParam> = [
        { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huksAlg },
        { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN },
        { tag: huks.HuksTag.HUKS_TAG_DIGEST, value: digest },
      ];
      if (isEC) {
        properties.push({ tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: huks.HuksKeySize.HUKS_ECC_KEY_SIZE_256 });
      }
      properties.push({ tag: huks.HuksTag.HUKS_TAG_PADDING, value: padding });

      const options: huks.HuksOptions = {
        properties,
        inData: dataBytes
      };
      huks.initSession(keyTag, options, (initError, initResult) => {
        if (initError) {
          Logger.error(`failed:`, JSON.stringify(initError, null, 2));
          return;
        }
        const handle = initResult.handle;
        huks.finishSession(handle, options, (finishError, finishResult) => {
          if (finishError) {
            Logger.error(`failed:`, JSON.stringify(finishError, null, 2));
            this.abortHuksSession(handle);
            reject(new Error(`failed: ${finishError.code} - ${finishError.message}`));
            return;
          }
          const outData = finishResult.outData;
          if (!outData) {
            reject(new Error('The signature result is empty'));
            return;
          }
          try {
            const signatureBytes = RSACommonUtils.convertOutDataToUint8Array(outData);
            resolve(signatureBytes);
          } catch (conversionError) {
            reject(new Error(`Failed to process signature result: ${conversionError}`));
          }
        });
      });
    });
  }

  async verify(signature: string, message: string, keyTag: string): Promise<boolean> {
    const actualKeyTag = this.getKeyTagForOperation(keyTag, 'verify');
    const keyType = await this.detectKeyType(actualKeyTag);
    if (keyType === 'EC') {
      return await this.verifySignature(message, signature, keyTag, 'SHA256withECDSA');
    } else {
      return await this.verifySignature(message, signature, actualKeyTag, 'SHA512withRSA');
    }
  }

  async verifyWithAlgorithm(signature: string, message: string, keyTag: string, algorithm?: string): Promise<boolean> {
    const actualAlgorithm = algorithm || 'SHA512withRSA';
    const actualKeyTag = this.getKeyTagForOperation(keyTag, 'verify');
    return await this.verifySignature(message, signature, actualKeyTag, actualAlgorithm);
  }

  private async verifySignature(data: string, signatureBase64: string, keyTag: string,
    algorithm: string): Promise<boolean> {

    try {
      const dataBytes = RSACommonUtils.encodeToUtf8Bytes(data);
      const signatureBytes = RSACommonUtils.base64StringToUint8Array(signatureBase64);
      const isValid = await this.performHuksVerify(keyTag, dataBytes, signatureBytes, algorithm);
      if (!isValid) {
        throw new Error();
      }
      return true;
    } catch (error) {
      throw new Error(error);
    }
  }

  private async performHuksVerify(keyTag: string, dataBytes: Uint8Array, signatureBytes: Uint8Array,
    algorithm: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      let digest = huks.HuksKeyDigest.HUKS_DIGEST_SHA256;

      if (algorithm.includes('SHA512') || algorithm.includes('sha512')) {
        digest = huks.HuksKeyDigest.HUKS_DIGEST_SHA512;
      } else if (algorithm.includes('SHA1') || algorithm.includes('sha1')) {
        digest = huks.HuksKeyDigest.HUKS_DIGEST_SHA1;
      } else if (algorithm.includes('MD5') || algorithm.includes('md5')) {
        digest = huks.HuksKeyDigest.HUKS_DIGEST_MD5;
      }
      const isEC = algorithm.includes('ECDSA');
      const huksAlg = isEC ? huks.HuksKeyAlg.HUKS_ALG_ECC : huks.HuksKeyAlg.HUKS_ALG_RSA;
      const padding = isEC ? huks.HuksKeyPadding.HUKS_PADDING_NONE : huks.HuksKeyPadding.HUKS_PADDING_PKCS1_V1_5;
      const properties: Array<huks.HuksParam> = [
        { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huksAlg },
        { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY },
        { tag: huks.HuksTag.HUKS_TAG_DIGEST, value: digest },
        { tag: huks.HuksTag.HUKS_TAG_PADDING, value: padding },
      ];

      const options: huks.HuksOptions = {
        properties,
        inData: dataBytes
      };

      huks.initSession(keyTag, options, (initError, initResult) => {
        if (initError) {
          Logger.error(`failed:`, JSON.stringify(initError, null, 2));
          resolve(false);
          return;
        }
        const handle = initResult.handle;
        const updateOptions: huks.HuksOptions = {
          properties,
          inData: dataBytes
        };

        huks.updateSession(handle, updateOptions, (updateError, updateResult) => {
          if (updateError) {
            Logger.error(`failed:`, JSON.stringify(updateError, null, 2));
            this.abortHuksSession(handle);
            resolve(false);
            return;
          }
          const finishOptions: huks.HuksOptions = {
            properties,
            inData: signatureBytes
          };

          huks.finishSession(handle, finishOptions, (finishError, finishResult) => {
            if (finishError) {
              Logger.info(`error:`, JSON.stringify(finishError, null, 2));
              this.abortHuksSession(handle);
              resolve(false);
              return;
            }
            resolve(true);
          });
        });
      });
    });
  }

  async deletePrivateKey(keyTag: string): Promise<boolean> {
    try {
      const encryptKeyTag = `${keyTag}_encrypt`;
      const signKeyTag = `${keyTag}_sign`;
      const deleteEncrypt = await this.deleteHuksKey(encryptKeyTag);
      const deleteSign = await this.deleteHuksKey(signKeyTag);
      const success = deleteEncrypt && deleteSign;
      return success;
    } catch (error) {
      Logger.error(TAG, `deletePrivateKey failed: ${error}`);
      return false;
    }
  }

  private async deleteHuksKey(alias: string): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const options: huks.HuksOptions = { properties: [] };

      huks.isKeyItemExist(alias, options, (existError, existResult) => {
        if (existError || !existResult) {
          resolve(true);
          return;
        }
        huks.deleteKeyItem(alias, options, (deleteError) => {
          if (deleteError) {
            Logger.error(`failed:`, JSON.stringify(deleteError));
            resolve(false);
          } else {
            resolve(true);
          }
        });
      });
    });
  }

  private async getRawECPublicKey(keyTag: string): Promise<string> {
    try {
      const publicKeyDer = await this.getRawHuksPublicKey(keyTag);

      if (!publicKeyDer) {
        throw new Error('failed');
      }
      return publicKeyDer;

    } catch (error) {
      Logger.error(TAG, `getRawECPublicKey failed: ${error}`);
      throw error;
    }
  }

  async encrypt64(data: string, key: string): Promise<string> {
    try {
      const dataBytes = RSACommonUtils.base64StringToUint8Array(data);
      const actualKeyTag = this.getKeyTagForOperation(key, 'encrypt');
      const encryptedBytes = await this.performHuksEncrypt(actualKeyTag, dataBytes);
      return RSACommonUtils.uint8ArrayToBase64(encryptedBytes);
    } catch (error) {
      Logger.error(TAG, `encrypt64 failed: ${error}`);
      throw error;
    }
  }

  async decrypt64(data: string, key: string): Promise<string> {
    try {
      const decryptBytes = RSACommonUtils.base64StringToUint8Array(data);
      const actualKeyTag = this.getKeyTagForOperation(key, 'encrypt');
      const decryptedBytes = await this.performHuksDecrypt(actualKeyTag, decryptBytes);
      return RSACommonUtils.uint8ArrayToBase64(decryptedBytes);
    } catch (error) {
      Logger.error(TAG, `decrypt64 failed: ${error}`);
      throw error;
    }
  }

  async sign64(data: string, key: string): Promise<string> {
    try {
      const dataBytes = RSACommonUtils.base64StringToUint8Array(data);
      const actualKeyTag = this.getKeyTagForOperation(key, 'sign');
      const keyType = await this.detectKeyType(key);
      let signatureBytes: Uint8Array;
      if (keyType === 'EC') {
        signatureBytes = await this.performHuksSignWithAlgorithm(actualKeyTag, dataBytes, 'SHA256withECDSA');
      } else {
        signatureBytes = await this.performHuksSignWithAlgorithm(actualKeyTag, dataBytes, 'SHA512withRSA');
      }
      return RSACommonUtils.uint8ArrayToBase64(signatureBytes);
    } catch (error) {
      Logger.error(TAG, `sign64 failed: ${error}`);
      throw error;
    }
  }

  async sign64WithAlgorithm(data: string, key: string, algorithm?: string): Promise<string> {
    const actualAlgorithm = algorithm || 'SHA512withRSA';
    try {
      const dataBytes = RSACommonUtils.base64StringToUint8Array(data);
      const actualKeyTag = this.getKeyTagForOperation(key, 'sign');
      const signatureBytes = await this.performHuksSignWithAlgorithm(actualKeyTag, dataBytes, actualAlgorithm);
      return RSACommonUtils.uint8ArrayToBase64(signatureBytes);
    } catch (error) {
      Logger.error(TAG, `sign64WithAlgorithm failed: ${error}`);
      throw error;
    }
  }

  async verify64(data: string, secretToVerify: string, key: string): Promise<boolean> {
    try {
      const dataBytes = RSACommonUtils.base64StringToUint8Array(data);
      const signatureBytes = RSACommonUtils.base64StringToUint8Array(secretToVerify);
      const actualKeyTag = this.getKeyTagForOperation(key, 'verify');
      const keyType = await this.detectKeyType(key);
      let isValid: boolean = false;
      if (keyType === 'EC') {
        isValid = await this.performHuksVerify(actualKeyTag, dataBytes, signatureBytes, 'SHA256withECDSA');
      } else {
        isValid = await this.performHuksVerify(actualKeyTag, dataBytes, signatureBytes, 'SHA512withRSA');
      }
      return isValid;
    } catch (error) {
      Logger.error(TAG, `verify64 failed: ${error}`);
      return false;
    }
  }

  async verify64WithAlgorithm(message: string, signature: string, key: string, algorithm?: string): Promise<boolean> {
    const actualAlgorithm = algorithm || 'SHA512withRSA';
    try {
      const dataBytes = RSACommonUtils.base64StringToUint8Array(message);
      const signatureBytes = RSACommonUtils.base64StringToUint8Array(signature);
      const actualKeyTag = this.getKeyTagForOperation(key, 'verify');
      const isValid = await this.performHuksVerify(actualKeyTag, dataBytes, signatureBytes, actualAlgorithm);
      return isValid;
    } catch (error) {
      Logger.error(TAG, `verify64WithAlgorithm failed: ${error}`);
      return false;
    }
  }

  async encodedPublicKeyDER(keyTag: string): Promise<string> {
    try {
      const signDerBase64 = await this.exportHuksPublicKeyDER(keyTag);
      if (signDerBase64) {
        return signDerBase64;
      } else {
        return '';
      }
    } catch (error) {
      Logger.error(TAG, `getPublicKeyDER failed: ${error}`);
      return '';
    }
  }

  private async exportHuksPublicKeyDER(keyTag: string): Promise<string | null> {
    try {
      const rawDerBase64 = await this.getRawHuksPublicKey(keyTag);
      if (!rawDerBase64) {
        Logger.error(`getRawHuksPublicKey returned null for ${keyTag}`);
        return null;
      }
      const result = RSACommonUtils.derToPem(rawDerBase64, 'PUBLIC KEY');
      return result;
    } catch (error) {
      Logger.error(TAG, `exportHuksPublicKeyDER failed: ${error}`);
      return null;
    }
  }

  private async getRawHuksPublicKey(keyTag: string): Promise<string | null> {
    return new Promise<string | null>((resolve) => {
      keyTag = `${keyTag}_sign`
      const emptyOptions: huks.HuksOptions = { properties: [] };
      huks.exportKeyItem(keyTag, emptyOptions, (err: any, result: any) => {
        if (err) {
          Logger.error('failed:', JSON.stringify(err, null, 2));
          resolve(null);
          return;
        }
        const outDataObj = result.outData;
        if (!outDataObj) {
          Logger.error('outData does not exist');
          resolve(null);
          return;
        }

        try {
          const keys = Object.keys(outDataObj).map(Number);
          const length = Math.max(...keys) + 1;
          const uint8Array = new Uint8Array(length);

          for (let i = 0; i < length; i++) {
            uint8Array[i] = outDataObj[i] || 0;
          }

          const publicKeyDer = RSACommonUtils.uint8ArrayToBase64(uint8Array);
          resolve(publicKeyDer);
        } catch (error) {
          Logger.error('Error:', error);
          resolve(null);
        }
      });
    });
  }

  private async detectKeyType(keyTag: string): Promise<'RSA' | 'EC'> {
    try {
      const options: huks.HuksOptions = { properties: [] };
      return new Promise((resolve, reject) => {
        huks.getKeyItemProperties(keyTag, options, (err, result) => {
          if (result && result.properties) {
            const algProperty = result.properties.find(
              (p: any) => p.tag === huks.HuksTag.HUKS_TAG_ALGORITHM
            );
            if (algProperty) {
              if (algProperty.value === huks.HuksKeyAlg.HUKS_ALG_ECC) {
                resolve('EC');
              } else if (algProperty.value === huks.HuksKeyAlg.HUKS_ALG_RSA) {
                resolve('RSA');
              }
            }
          }
          resolve('RSA');
        });
      });
    } catch (error) {
      Logger.error(TAG, `detectKeyType failed: ${error}`);
      return 'RSA';
    }
  }

  async getPublicKey(keyTag: string): Promise<{ public: string } | null> {
    try {
      const publicKey = await this.encodedPublicKey(keyTag);
      if (publicKey) {
        return { public: publicKey };
      }
      return null;
    } catch (error) {
      Logger.error(TAG, `getPublicKey failed: ${error}`);
      return null;
    }
  }

  async getPublicKeyRSA(keyTag: string): Promise<{ public: string } | null> {
    try {
      const publicKey = await this.encodedPublicKeyRSA(keyTag);
      if (publicKey) {
        return { public: publicKey };
      }
      return null;
    } catch (error) {
      Logger.error(TAG, `getPublicKeyRSA failed: ${error}`);
      return null;
    }
  }

  async getPublicKeyDER(keyTag: string): Promise<{ public: string } | null> {
    try {
      const publicKey = await this.encodedPublicKeyDER(keyTag);
      if (publicKey) {
        return { public: publicKey };
      }
      return null;
    } catch (error) {
      Logger.error(TAG, `getPublicKeyDER failed: ${error}`);
      return null;
    }
  }

  async encodedPublicKey(keyTag: string): Promise<string | null> {
    try {
      const publicKeyDer = await this.getRawHuksPublicKey(keyTag);
      if (!publicKeyDer) {
        Logger.error(`failed to get raw public key for ${keyTag}`);
        return null;
      }
      const rawBytes = RSACommonUtils.base64StringToUint8Array(publicKeyDer);
      try {
        const pkcs1Bytes = this.extractPKCS1FromX509(rawBytes);
        const pkcs1Base64 = RSACommonUtils.uint8ArrayToBase64(pkcs1Bytes);
        return RSACommonUtils.derToPem(pkcs1Base64, 'PUBLIC KEY');
      } catch (conversionError) {
        Logger.error(TAG, `extractPKCS1FromX509 failed: ${conversionError}`);
        return RSACommonUtils.derToPem(publicKeyDer, 'PUBLIC KEY');
      }
    } catch (error) {
      Logger.error(TAG, `encodedPublicKey failed: ${error}`);
      return null;
    }
  }

  async encodedPublicKeyRSA(keyTag: string): Promise<string | null> {
    try {
      const publicKeyDer = await this.getRawHuksPublicKey(keyTag);
      if (!publicKeyDer) {
        Logger.error('failed to get raw public key');
        return null;
      }
      const rawBytes = RSACommonUtils.base64StringToUint8Array(publicKeyDer);
      try {
        const pkcs1Bytes = this.extractPKCS1FromX509(rawBytes);
        const pkcs1Base64 = RSACommonUtils.uint8ArrayToBase64(pkcs1Bytes);
        return RSACommonUtils.derToPem(pkcs1Base64, 'RSA PUBLIC KEY');
      } catch (conversionError) {
        Logger.error(TAG, `extractPKCS1FromX509 failed for RSA: ${conversionError}`);
        return RSACommonUtils.derToPem(publicKeyDer, 'RSA PUBLIC KEY');
      }
    } catch (error) {
      Logger.error(TAG, `encodedPublicKeyRSA failed: ${error}`);
      return null;
    }
  }

  private extractPKCS1FromX509(x509Der: Uint8Array): Uint8Array {
    let index = 0;
    if (x509Der[index] !== 0x30) throw new Error('Not a valid X.509');
    index++;

    if (x509Der[index] === 0x82) {
      index += 3;
      index += 15;
      if (x509Der[index] !== 0x03) {
        throw new Error('Expected BIT STRING');
      }
      index++;
      if (x509Der[index] === 0x82) {
        const bsLenHigh = x509Der[index + 1];
        const bsLenLow = x509Der[index + 2];
        const bitStringLength = (bsLenHigh << 8) | bsLenLow;
        index += 3;
        if (x509Der[index] === 0x00) {
          index++;
        }
        const pkcs1Length = bitStringLength - 1;
        const pkcs1Bytes = new Uint8Array(pkcs1Length);
        pkcs1Bytes.set(x509Der.slice(index, index + pkcs1Length));

        return pkcs1Bytes;
      }
    }

    throw new Error('Could not extract PKCS#1 from X.509');
  }

  async generateCSR(keyTag: string, CN: string, withAlgorithm?: string): Promise<{ csr: string }> {
    if (deviceInfo.sdkApiVersion < 18) {
      return { csr: 'Not supported yet' };
    }
    try {
      const algorithm = withAlgorithm || 'SHA256withRSA';
      const keyPair = await this.generateTempKeyPairForCSR(2048);
      const csrPEM = await this.createCSRWithKeyPair(CN, algorithm, keyPair);
      await this.storePublicKeyToHuks(keyTag, keyPair.pubKeyBlob);
      return { csr: csrPEM };
    } catch (error) {
      Logger.error(TAG, `generateCSR failed: ${error}`);
      throw error;
    }
  }

  private async generateTempKeyPairForCSR(keySize: number): Promise<{
    priKey: cryptoFramework.PriKey;
    pubKey: cryptoFramework.PubKey;
    priKeyBlob: cryptoFramework.DataBlob;
    pubKeyBlob: cryptoFramework.DataBlob;
  }> {
    try {
      const rsaAlg = keySize === 2048 ? 'RSA2048' :
        keySize === 1024 ? 'RSA1024' : 'RSA4096';
      const rsaGenerator = cryptoFramework.createAsyKeyGenerator(rsaAlg);
      const keyPair = await rsaGenerator.generateKeyPair();
      const priKeyBlob = await keyPair.priKey.getEncoded();
      const pubKeyBlob = await keyPair.pubKey.getEncoded();
      return {
        priKey: keyPair.priKey,
        pubKey: keyPair.pubKey,
        priKeyBlob,
        pubKeyBlob
      };

    } catch (error) {
      throw new Error(`Error: ${error}`);
    }
  }

  private async createCSRWithKeyPair(
    commonName: string,
    algorithm: string,
    keyPair: {
      priKey: cryptoFramework.PriKey;
      priKeyBlob: cryptoFramework.DataBlob;
      pubKeyBlob: cryptoFramework.DataBlob;
    }
  ): Promise<string> {
    try {
      const privateKeyDer = new Uint8Array(keyPair.priKeyBlob.data);
      const privateKeyBase64 = RSACommonUtils.uint8ArrayToBase64(privateKeyDer);
      const privateKeyPem = RSACommonUtils.derToPem(privateKeyBase64, 'PRIVATE KEY');
      const dnString = `CN=${commonName}`;
      const realDnStr = '/' + dnString.replace(/,/g, '/').replace(/=/g, '=');
      let mdName = 'SHA256';
      if (algorithm.includes('SHA512')) {
        mdName = 'SHA512';
      } else if (algorithm.includes('SHA1')) {
        mdName = 'SHA1';
      }
      const x500Name = await cert.createX500DistinguishedName(realDnStr);
      const conf: cert.CsrGenerationConfig = {
        subject: x500Name,
        mdName: mdName,
        outFormat: cert.EncodingBaseFormat.PEM,
      };
      const privateKeyInfo: cert.PrivateKeyInfo = {
        key: privateKeyPem
      };
      const csrStr = cert.generateCsr(privateKeyInfo, conf).toString();
      if (!csrStr.includes('-----BEGIN CERTIFICATE REQUEST-----') ||
        !csrStr.includes('-----END CERTIFICATE REQUEST-----')) {
        throw new Error('Error');
      }
      return csrStr;
    } catch (error: any) {
      throw new Error(`Error: ${error.message}`);
    }
  }

  private async storePublicKeyToHuks(keyTag: string, pubKeyBlob: cryptoFramework.DataBlob): Promise<void> {
    try {
      const properties: Array<huks.HuksParam> = [
        { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_RSA },
        { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: huks.HuksKeySize.HUKS_RSA_KEY_SIZE_2048 },
        { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY },
        { tag: huks.HuksTag.HUKS_TAG_PADDING, value: huks.HuksKeyPadding.HUKS_PADDING_PKCS1_V1_5 },
        { tag: huks.HuksTag.HUKS_TAG_DIGEST, value: huks.HuksKeyDigest.HUKS_DIGEST_SHA256 },
        { tag: huks.HuksTag.HUKS_TAG_IS_KEY_ALIAS, value: true },
      ];
      const keyData = new Uint8Array(pubKeyBlob.data.length);
      keyData.set(new Uint8Array(pubKeyBlob.data), 0);

      const options: huks.HuksOptions = {
        properties,
        inData: keyData
      };
      const checkOptions: huks.HuksOptions = { properties: [] };
      return new Promise<void>((resolve, reject) => {
        huks.isKeyItemExist(keyTag, checkOptions, (existError, existResult) => {
          if (existError) {
            Logger.info(`Error:`, JSON.stringify(existError));
          }

          if (existResult) {
            huks.deleteKeyItem(keyTag, checkOptions, (deleteError) => {
              if (deleteError) {
                Logger.info(`Error:`, JSON.stringify(deleteError));
              }
              proceedWithImport();
            });
          } else {
            proceedWithImport();
          }
        });
        const proceedWithImport = () => {
          huks.importKeyItem(keyTag, options, (importError) => {
            if (importError) {
              Logger.info(`Error:`, JSON.stringify(importError));
            } else {
              Logger.info(`success`);
            }
            resolve();
          });
        };
      });
    } catch (error) {
      Logger.error(`Error:`,error);
    }
  }

  getConstants(): Object {
    let result = {
      SHA256withRSA: 'SHA256withRSA',
      SHA512withRSA: 'SHA512withRSA',
      SHA1withRSA: 'SHA1withRSA',
      SHA256withECDSA: 'SHA256withECDSA',
      SHA512withECDSA: 'SHA512withECDSA',
      SHA1withECDSA: 'SHA1withECDSA',
    }
    return result;
  };
}
import Logger from './Logger';
import { AnyThreadTurboModule, AnyThreadTurboModuleContext } from '@rnoh/react-native-openharmony/ts';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { RSACommonUtils } from './RSACommonUtils';

const TAG = '[RNRSA]';

export class RNRSAModule extends AnyThreadTurboModule {
  constructor(ctx: AnyThreadTurboModuleContext) {
    super(ctx);
    Logger.info(TAG, 'RNRSA module initialized');
  }

  async generate(): Promise<{ public: string }> {
    try {
      return await this.generateKeys(2048);
    } catch (error) {
      Logger.error('failed:', error);
      throw error;
    }
  }

  async generateKeys(keySize: number): Promise<{ private: string; public: string }> {
    try {
      const rsaGenerator = cryptoFramework.createAsyKeyGenerator('RSA' + keySize);
      const keyPair = await rsaGenerator.generateKeyPair();
      const privateKeyPem = keyPair.priKey.getEncodedPem('PKCS1');
      const publicKeyPem = keyPair.pubKey.getEncodedPem('X509');

      return {
        private: privateKeyPem,
        public: publicKeyPem
      };
    } catch (error) {
      Logger.error('failed:', error);
      return { private: '', public: '' };
    }
  }

  async encrypt(data: string, key: string): Promise<string> {
    try {
      const keySize = RSACommonUtils.getKeySizeFromPem(key);
      const rsaGenerator = cryptoFramework.createAsyKeyGenerator(`RSA${keySize}`);
      let keyBlob: cryptoFramework.DataBlob = RSACommonUtils.stringToKeyBlob(key);
      const keyPair = await rsaGenerator.convertKey(keyBlob, null);
      const cipher = cryptoFramework.createCipher(`RSA${keySize}|PKCS1`);
      await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, keyPair.pubKey, null);
      const dataArray = RSACommonUtils.encodeToUtf8Bytes(data);
      const encryptedBlob = await cipher.doFinal({ data: dataArray });
      return RSACommonUtils.uint8ArrayToBase64WithLineBreaks(encryptedBlob.data);
    } catch (error) {
      Logger.error('failed:', error);
      return '';
    }
  }

  async decrypt(data: string, key: string): Promise<string> {
    try {
      const keySize = RSACommonUtils.getKeySizeFromPem(key);
      const rsaGenerator = cryptoFramework.createAsyKeyGenerator(`RSA${keySize}`);
      let keyBlob: cryptoFramework.DataBlob = RSACommonUtils.stringToKeyBlob(key);
      const keyPair = await rsaGenerator.convertKey(null, keyBlob);
      const cipher = cryptoFramework.createCipher(`RSA${keySize}|PKCS1`);
      await cipher.init(cryptoFramework.CryptoMode.DECRYPT_MODE, keyPair.priKey, null);
      const encryptedData = RSACommonUtils.base64StringToUint8ArrayWithLineBreaks(data);
      if (encryptedData.length === 0) {
        return '';
      }
      const dataBlob: any = { data: encryptedData };
      const decryptedBlob = await cipher.doFinal(dataBlob);

      if (decryptedBlob.data.length === 0) {
        Logger.error('failed');
        return '';
      }
      return RSACommonUtils.decodeFromUtf8Bytes(decryptedBlob.data);
    } catch (error) {
      return '';
    }
  }

  async sign(data: string, key: string): Promise<string> {
    try {
      return await this.signWithAlgorithm(data, key, 'SHA512withRSA');
    } catch (error) {
      Logger.error('failed:', error);
      throw new Error(error instanceof Error ? error.message : 'sign failed');
    }
  }

  async signWithAlgorithm(data: string, key: string, algorithm?: string): Promise<string> {
    try {
      const actualAlgorithm = algorithm || 'SHA512withRSA';
      const keySize = RSACommonUtils.getKeySizeFromPem(key);
      const rsaGenerator = cryptoFramework.createAsyKeyGenerator(`RSA${keySize}`);
      let keyBlob: cryptoFramework.DataBlob = RSACommonUtils.stringToKeyBlob(key);
      const keyPair = await rsaGenerator.convertKey(null, keyBlob);
      const hkAlgorithm = RSACommonUtils.getHMAlgorithm(actualAlgorithm, keySize);
      const signer = cryptoFramework.createSign(hkAlgorithm);
      await signer.init(keyPair.priKey);
      const dataArray = RSACommonUtils.encodeToUtf8Bytes(data);
      const signature = await signer.sign({ data: dataArray });
      return RSACommonUtils.uint8ArrayToBase64(signature.data);
    } catch (error) {
      Logger.error('failed:', error);
      throw error;
    }
  }

  async verify(signature: string, data: string, key: string): Promise<boolean> {
    return await this.verifyWithAlgorithm(signature, data, key, 'SHA512withRSA');
  }

  async verifyWithAlgorithm(
    signature: string,
    data: string,
    key: string,
    algorithm?: string
  ): Promise<boolean> {
    try {
      const actualAlgorithm = algorithm || 'SHA512withRSA';
      const keySize = RSACommonUtils.getKeySizeFromPem(key);
      const rsaGenerator = cryptoFramework.createAsyKeyGenerator(`RSA${keySize}`);
      let keyBlob: cryptoFramework.DataBlob = RSACommonUtils.stringToKeyBlob(key);
      const keyPair = await rsaGenerator.convertKey(keyBlob, null);
      const hkAlgorithm = RSACommonUtils.getHMAlgorithm(actualAlgorithm, keySize);

      const verifier = cryptoFramework.createVerify(hkAlgorithm);
      await verifier.init(keyPair.pubKey);

      const dataArray = RSACommonUtils.encodeToUtf8Bytes(data);
      const signatureArray = RSACommonUtils.base64StringToUint8Array(signature);
      const isValid = await verifier.verify({ data: dataArray }, { data: signatureArray });
      if (!isValid) {
        throw new Error();
      }
      return true;
    } catch (error) {
      throw new Error(error);
    }
  }

  async encrypt64(data: string, key: string): Promise<string> {
    try {
      const decodedBytes = RSACommonUtils.base64StringToUint8Array(data);
      const keySize = RSACommonUtils.getKeySizeFromPem(key);
      const rsaGenerator = cryptoFramework.createAsyKeyGenerator(`RSA${keySize}`);
      let keyBlob: cryptoFramework.DataBlob = RSACommonUtils.stringToKeyBlob(key);
      const keyPair = await rsaGenerator.convertKey(keyBlob, null);
      const cipher = cryptoFramework.createCipher(`RSA${keySize}|PKCS1`);
      await cipher.init(cryptoFramework.CryptoMode.ENCRYPT_MODE, keyPair.pubKey, null);
      const encryptedBlob = await cipher.doFinal({ data: decodedBytes });
      return RSACommonUtils.uint8ArrayToBase64(encryptedBlob.data);
    } catch (error) {
      Logger.error('failed:', error);
      throw new Error(error instanceof Error ? error.message : 'encrypt64 failed');
    }
  }

  async decrypt64(data: string, key: string): Promise<string> {
    try {
      const decodedBytes = RSACommonUtils.base64StringToUint8Array(data);
      const keySize = RSACommonUtils.getKeySizeFromPem(key);
      const rsaGenerator = cryptoFramework.createAsyKeyGenerator(`RSA${keySize}`);
      let keyBlob: cryptoFramework.DataBlob = RSACommonUtils.stringToKeyBlob(key);
      const keyPair = await rsaGenerator.convertKey(null, keyBlob);
      const cipher = cryptoFramework.createCipher(`RSA${keySize}|PKCS1`);
      await cipher.init(cryptoFramework.CryptoMode.DECRYPT_MODE, keyPair.priKey, null);
      const decryptedBlob = await cipher.doFinal({ data: decodedBytes });
      return RSACommonUtils.uint8ArrayToBase64(decryptedBlob.data);
    } catch (error) {
      Logger.error('failed:', error);
      throw new Error(error instanceof Error ? error.message : 'decrypt64 failed');
    }
  }

  async sign64(data: string, key: string): Promise<string> {
    try {
      return this.sign64WithAlgorithm(data, key, 'SHA512withRSA');
    } catch (error) {
      Logger.error('failed:', error);
      throw new Error(error instanceof Error ? error.message : 'sign64 failed');
    }
  }

  async sign64WithAlgorithm(data: string, key: string, algorithm?: string): Promise<string> {
    const actualAlgorithm = algorithm || 'SHA512withRSA';
    try {
      const decodedBytes = RSACommonUtils.base64StringToUint8Array(data);
      const keySize = RSACommonUtils.getKeySizeFromPem(key);
      const rsaGenerator = cryptoFramework.createAsyKeyGenerator(`RSA${keySize}`);
      let keyBlob: cryptoFramework.DataBlob = RSACommonUtils.stringToKeyBlob(key);
      const keyPair = await rsaGenerator.convertKey(null, keyBlob);
      const hkAlgorithm = RSACommonUtils.getHMAlgorithm(actualAlgorithm, keySize);
      const signer = cryptoFramework.createSign(hkAlgorithm);
      await signer.init(keyPair.priKey);
      const signature = await signer.sign({ data: decodedBytes });
      return RSACommonUtils.uint8ArrayToBase64(signature.data);
    } catch (error) {
      Logger.error('failed:', error);
      throw new Error(error instanceof Error ? error.message : 'sign64WithAlgorithm failed');
    }
  }

  async verify64(data: string, signature: string, key: string): Promise<boolean> {
    try {
      return this.verify64WithAlgorithm(data, signature, key, 'SHA512withRSA');
    } catch (error) {
      throw new Error(error);
    }
  }

  async verify64WithAlgorithm(data: string, signature: string, key: string, algorithm?: string): Promise<boolean> {
    try {
      const actualAlgorithm = algorithm || 'SHA512withRSA';
      const decodedBytes = RSACommonUtils.base64StringToUint8Array(data);
      const signatureBytes = RSACommonUtils.base64StringToUint8Array(signature);
      const keySize = RSACommonUtils.getKeySizeFromPem(key);
      const rsaGenerator = cryptoFramework.createAsyKeyGenerator(`RSA${keySize}`);
      let keyBlob: cryptoFramework.DataBlob = RSACommonUtils.stringToKeyBlob(key);
      const keyPair = await rsaGenerator.convertKey(keyBlob, null);
      const hkAlgorithm = RSACommonUtils.getHMAlgorithm(actualAlgorithm, keySize);

      const verifier = cryptoFramework.createVerify(hkAlgorithm);
      await verifier.init(keyPair.pubKey);
      const isValid = await verifier.verify({ data: decodedBytes }, { data: signatureBytes });
      if (!isValid) {
        throw new Error();
      }
      return true;
    } catch (error) {
      throw new Error(error);
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
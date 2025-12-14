import { util } from '@kit.ArkTS';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import Logger from './Logger';

export class RSACommonUtils {
  public static encodeToUtf8Bytes(str: string): Uint8Array {
    try {
      const encoded = encodeURIComponent(str);
      const bytes: number[] = [];
      let i = 0;

      while (i < encoded.length) {
        if (encoded[i] === '%') {
          const hex = encoded.substring(i + 1, i + 3);
          bytes.push(parseInt(hex, 16));
          i += 3;
        } else {
          bytes.push(encoded.charCodeAt(i));
          i += 1;
        }
      }

      return new Uint8Array(bytes);
    } catch (error) {
      Logger.error('failed:', error);
      return new Uint8Array(0);
    }
  }

  public static decodeFromUtf8Bytes(bytes: Uint8Array): string {
    try {
      let encoded = '';
      for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i];

        if (byte < 0x20 || byte >= 0x7F || byte === 0x25) {
          encoded += '%' + byte.toString(16).padStart(2, '0').toUpperCase();
        } else {
          encoded += String.fromCharCode(byte);
        }
      }
      return decodeURIComponent(encoded);

    } catch (error) {
      Logger.error('failed:', error);
      return '';
    }
  }

  public static base64StringToUint8Array(base64Str: string): Uint8Array {
    try {
      const cleanBase64 = base64Str.replace(/[^A-Za-z0-9+/=]/g, '');
      if (cleanBase64.length % 4 !== 0) {
        const paddedLength = Math.ceil(cleanBase64.length / 4) * 4;
        const paddedBase64 = cleanBase64.padEnd(paddedLength, '=');
        return RSACommonUtils.decodeBase64WithHelper(paddedBase64);
      }
      return RSACommonUtils.decodeBase64WithHelper(cleanBase64);
    } catch (error) {
      Logger.error('failed', error.message);
      throw new Error(`failed ${error.message}`);
    }
  }

  private static decodeBase64WithHelper(base64Str: string): Uint8Array {
    try {
      const base64Helper = new util.Base64Helper();
      const uint8Array = base64Helper.decodeSync(base64Str);
      return uint8Array;
    } catch (error) {
      Logger.error('failed:', error.message);
      return new Uint8Array(0);
    }
  }

  public static uint8ArrayToBase64(uint8Array: Uint8Array): string {
    try {
      const base64Helper = new util.Base64Helper();
      const base64Str = base64Helper.encodeToStringSync(uint8Array);
      return base64Str;
    } catch (error) {
      Logger.error('failed:', error.message);
      return '';
    }
  }

  public static uint8ArrayToBase64WithLineBreaks(uint8Array: Uint8Array): string {
    try {
      const base64Helper = new util.Base64Helper();
      const base64Str = base64Helper.encodeToStringSync(uint8Array);

      if (base64Str.length <= 64) {
        return base64Str;
      }
      return base64Str.replace(/(.{64})/g, '$1\n').trim();
    } catch (error) {
      Logger.error(`failed: ${error.message}`);
      return '';
    }
  }

  public static base64StringToUint8ArrayWithLineBreaks(base64Str: string): Uint8Array {
    try {
      const cleanBase64 = base64Str.replace(/\s+/g, '');
      return RSACommonUtils.base64StringToUint8Array(cleanBase64);
    } catch (error) {
      Logger.error('failed:', error.message);
      throw new Error(`failed: ${error.message}`);
    }
  }

  public static extractBase64FromPem(pem: string): string {
    const lines = pem.split('\n');
    let base64 = '';

    for (let i = 1; i < lines.length - 1; i++) {
      const line = lines[i].trim();
      if (line && !line.startsWith('-----')) {
        base64 += line;
      }
    }
    return base64;
  }

  public static getKeySizeFromPem(pem: string): number {
    const base64 = RSACommonUtils.extractBase64FromPem(pem);
    if (pem.includes('PRIVATE KEY')) {
      if (base64.length > 3000) {
        return 4096;
      } else if (base64.length > 1500) {
        return 2048;
      } else if (base64.length > 700) {
        return 1024;
      }
    } else if (pem.includes('PUBLIC KEY')) {
      if (base64.length > 700) {
        return 4096;
      } else if (base64.length > 350) {
        return 2048;
      } else if (base64.length > 180) {
        return 1024;
      }
    }
    return 2048;
  }

  public static stringToKeyBlob(key: string): cryptoFramework.DataBlob {
    if (key.includes('-----BEGIN')) {
      const pemContent = key
        .replace(/-----BEGIN.*-----/g, '')
        .replace(/-----END.*-----/g, '')
        .replace(/\s+/g, '');
      return { data: RSACommonUtils.base64StringToUint8Array(pemContent) };
    }
    return { data: new Uint8Array(0) };
  }

  public static derToPem(
    derBase64: string,
    keyType: 'PUBLIC KEY' | 'RSA PUBLIC KEY' | 'PRIVATE KEY' | 'RSA PRIVATE KEY'
  ): string {
    const cleanBase64 = derBase64.replace(/\s+/g, '');
    const chunks: string[] = [];
    for (let i = 0; i < cleanBase64.length; i += 64) {
      chunks.push(cleanBase64.slice(i, i + 64));
    }
    const header = `-----BEGIN ${keyType}-----\n`;
    const footer = `\n-----END ${keyType}-----`;
    return header + chunks.join('\n') + footer;
  }

  public static getHMAlgorithm(algorithm: string, keySize: number): string {
    const algorithmMap: Record<string, string> = {
      'SHA256withRSA': `RSA${keySize}|PKCS1|SHA256`,
      'SHA512withRSA': `RSA${keySize}|PKCS1|SHA512`,
      'SHA1withRSA': `RSA${keySize}|PKCS1|SHA1`,
    };
    return algorithmMap[algorithm] || `RSA${keySize}|PKCS1|SHA512`;
  }

  public static convertOutDataToUint8Array(outDataObj: Uint8Array): Uint8Array {
    const keys = Object.keys(outDataObj).map(Number);
    const length = Math.max(...keys) + 1;
    const result = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      result[i] = outDataObj[i] || 0;
    }
    return result;
  }
}
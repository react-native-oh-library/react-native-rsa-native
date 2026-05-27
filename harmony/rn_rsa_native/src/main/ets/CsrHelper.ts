import { RSACommonUtils } from './RSACommonUtils';

const SEQUENCE_TAG = 0x30;
const SET_TAG = 0x31;
const OBJECT_CN = [0x06, 0x03, 0x55, 0x04, 0x03];

const SEQUENCE_SHA256_RSA = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00];
const SEQUENCE_SHA512_RSA = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00];
const SEQUENCE_SHA1_RSA = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00];
const SEQUENCE_SHA256_ECDSA = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const SEQUENCE_SHA512_ECDSA = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const SEQUENCE_SHA1_ECDSA = [0x30, 0x0a, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];

export class CsrHelper {
  static getSignatureAlgorithmIdentifier(algorithm: string): Uint8Array {
    const lower = algorithm.toLowerCase();
    if (lower.includes('ecdsa')) {
      if (lower.includes('sha512')) {
        return new Uint8Array(SEQUENCE_SHA512_ECDSA);
      }
      if (lower.includes('sha1')) {
        return new Uint8Array(SEQUENCE_SHA1_ECDSA);
      }
      return new Uint8Array(SEQUENCE_SHA256_ECDSA);
    }
    if (lower.includes('sha512')) {
      return new Uint8Array(SEQUENCE_SHA512_RSA);
    }
    if (lower.includes('sha1')) {
      return new Uint8Array(SEQUENCE_SHA1_RSA);
    }
    return new Uint8Array(SEQUENCE_SHA256_RSA);
  }

  static buildCertificationRequestInfo(commonName: string, subjectPublicKeyInfoDer: Uint8Array): Uint8Array {
    const version = new Uint8Array([0x02, 0x01, 0x00]);
    const subject = CsrHelper.buildSubject(commonName);
    const attributes = new Uint8Array([0xa0, 0x00]);

    let certificationRequestInfo = CsrHelper.concat(version, subject, subjectPublicKeyInfoDer, attributes);
    certificationRequestInfo = CsrHelper.enclose(certificationRequestInfo, SEQUENCE_TAG);
    return certificationRequestInfo;
  }

  static buildCsr(
    certificationRequestInfo: Uint8Array,
    signature: Uint8Array,
    algorithm: string
  ): Uint8Array {
    const algorithmIdentifier = CsrHelper.getSignatureAlgorithmIdentifier(algorithm);
    const signatureBitString = CsrHelper.buildBitString(signature);

    let certificationRequest = CsrHelper.concat(
      certificationRequestInfo,
      algorithmIdentifier,
      signatureBitString
    );
    certificationRequest = CsrHelper.enclose(certificationRequest, SEQUENCE_TAG);
    return certificationRequest;
  }

  static buildCsrPem(
    commonName: string,
    subjectPublicKeyInfoDer: Uint8Array,
    signature: Uint8Array,
    algorithm: string
  ): string {
    const certificationRequestInfo = CsrHelper.buildCertificationRequestInfo(commonName, subjectPublicKeyInfoDer);
    const csrDer = CsrHelper.buildCsr(certificationRequestInfo, signature, algorithm);
    const base64 = RSACommonUtils.uint8ArrayToBase64(csrDer);
    return CsrHelper.wrapPem(base64);
  }

  private static buildSubject(commonName: string): Uint8Array {
    let subjectItem = new Uint8Array(OBJECT_CN);
    subjectItem = CsrHelper.concat(subjectItem, CsrHelper.encodeUtf8String(commonName));
    subjectItem = CsrHelper.enclose(subjectItem, SEQUENCE_TAG);
    subjectItem = CsrHelper.enclose(subjectItem, SET_TAG);
    return CsrHelper.enclose(subjectItem, SEQUENCE_TAG);
  }

  private static encodeUtf8String(value: string): Uint8Array {
    const utf8 = RSACommonUtils.encodeToUtf8Bytes(value);
    const lengthBytes = CsrHelper.encodeDerLength(utf8.length);
    const result = new Uint8Array(1 + lengthBytes.length + utf8.length);
    result[0] = 0x0c;
    result.set(lengthBytes, 1);
    result.set(utf8, 1 + lengthBytes.length);
    return result;
  }

  private static buildBitString(signature: Uint8Array): Uint8Array {
    const withUnusedBits = new Uint8Array(1 + signature.length);
    withUnusedBits[0] = 0x00;
    withUnusedBits.set(signature, 1);
    return CsrHelper.enclose(withUnusedBits, 0x03);
  }

  private static enclose(data: Uint8Array, tag: number): Uint8Array {
    const lengthBytes = CsrHelper.encodeDerLength(data.length);
    const result = new Uint8Array(1 + lengthBytes.length + data.length);
    result[0] = tag;
    result.set(lengthBytes, 1);
    result.set(data, 1 + lengthBytes.length);
    return result;
  }

  private static encodeDerLength(length: number): Uint8Array {
    if (length < 128) {
      return new Uint8Array([length]);
    }
    if (length < 0x100) {
      return new Uint8Array([0x81, length]);
    }
    if (length < 0x10000) {
      return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
    }
    throw new Error(`DER length too large: ${length}`);
  }

  private static concat(...parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }

  static wrapPem(base64: string): string {
    const lines: string[] = [];
    for (let i = 0; i < base64.length; i += 64) {
      lines.push(base64.slice(i, i + 64));
    }
    return `-----BEGIN CERTIFICATE REQUEST-----\n${lines.join('\n')}\n-----END CERTIFICATE REQUEST-----\n`;
  }
}

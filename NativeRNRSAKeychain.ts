import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';
import type { Double } from 'react-native/Libraries/Types/CodegenTypes';

export interface Spec extends TurboModule {
  generate(keyTag: string): Promise<{ public: string }>;
  generateEC(keyTag: string): Promise<{ public: string }>;
  generateCSR(keyTag: string, CN: string, signature?: string): Promise<{ csr: string }>;
  generateKeys(keyTag: string, keySize: Double): Promise<{ public: string }>;
  generateCSRWithEC(cn: string, keyTag: string, keySize: Double): Promise<{ public: string; csr: string }>;
  
  encrypt(data: string, keyTag: string): Promise<string>;
  decrypt(data: string, keyTag: string): Promise<string>;
  encrypt64(data: string, keyTag: string): Promise<string>;
  decrypt64(data: string, keyTag: string): Promise<string>;
  
  sign(data: string, keyTag: string): Promise<string>;
  signWithAlgorithm(data: string, keyTag: string, signature?: string): Promise<string>;
  sign64WithAlgorithm(data: string, keyTag: string, signature?: string): Promise<string>;
  verify(data: string, secretToVerify: string, keyTag: string): Promise<boolean>;
  verifyWithAlgorithm(data: string, secretToVerify: string, keyTag: string, signature?: string): Promise<boolean>;
  verify64WithAlgorithm(data: string, secretToVerify: string, keyTag: string, signature?: string): Promise<boolean>;
  
  deletePrivateKey(keyTag: string): Promise<boolean>;
  getPublicKey(keyTag: string): Promise<string | null>;
  getPublicKeyDER(keyTag: string): Promise<string | null>;
  getPublicKeyRSA(keyTag: string): Promise<string | null>;

  getConstants(): Object;
}

export default TurboModuleRegistry.getEnforcing<Spec>("RNRSAKeychain");
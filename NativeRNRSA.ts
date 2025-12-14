import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';
import type { Double } from 'react-native/Libraries/Types/CodegenTypes';

export interface Spec extends TurboModule {
  generate(): Promise<{ public: string }>;
  generateKeys(keySize: Double): Promise<{ private: string; public: string }>;

  encrypt(data: string, key: string): Promise<string>;
  decrypt(data: string, key: string): Promise<string>;
  encrypt64(data: string, key: string): Promise<string>;
  decrypt64(data: string, key: string): Promise<string>;
  
  sign(data: string, key: string): Promise<string>;
  signWithAlgorithm(data: string, key: string, signature?: string): Promise<string>;
  sign64(data: string, key: string): Promise<string>;
  sign64WithAlgorithm(data: string, key: string, signature?: string): Promise<string>;
  verify(data: string, secretToVerify: string, key: string): Promise<boolean>;
  verifyWithAlgorithm(data: string, secretToVerify: string, key: string, signature?: string): Promise<boolean>;
  verify64(data: string, secretToVerify: string, key: string): Promise<boolean>;
  verify64WithAlgorithm(data: string, secretToVerify: string, key: string, signature?: string): Promise<boolean>;

  getConstants(): Object;
}

export default TurboModuleRegistry.getEnforcing<Spec>("RNRSA");
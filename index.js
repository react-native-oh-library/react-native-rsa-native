import { NativeModules } from 'react-native';
import { TurboModuleRegistry } from "react-native";

var RNRSA = TurboModuleRegistry ? TurboModuleRegistry.get('RNRSA') : NativeModules.RNRSA;
var RNRSAKeychain = TurboModuleRegistry ? TurboModuleRegistry.get('RNRSAKeychain') : NativeModules.RNRSAKeychain;

var RSA = {
    SHA256withRSA: RNRSA.getConstants().SHA256withRSA,
    SHA512withRSA: RNRSA.getConstants().SHA512withRSA,
    SHA1withRSA: RNRSA.getConstants().SHA1withRSA,
    SHA256withECDSA: RNRSA.getConstants().SHA256withECDSA,
    SHA512withECDSA: RNRSA.getConstants().SHA512withECDSA,
    SHA1withECDSA: RNRSA.getConstants().SHA1withECDSA,
    generate:  RNRSA.generate.bind(RNRSA),
    generateKeys:  RNRSA.generateKeys.bind(RNRSA),
    encrypt:  RNRSA.encrypt.bind(RNRSA),
    decrypt:  RNRSA.decrypt.bind(RNRSA),
    encrypt64:  RNRSA.encrypt64.bind(RNRSA),
    decrypt64:  RNRSA.decrypt64.bind(RNRSA),
    sign:  RNRSA.sign.bind(RNRSA),
    signWithAlgorithm:  RNRSA.signWithAlgorithm.bind(RNRSA),
    sign64:  RNRSA.sign64.bind(RNRSA),
    sign64WithAlgorithm:  RNRSA.sign64WithAlgorithm.bind(RNRSA),
    verify:  RNRSA.verify.bind(RNRSA),
    verifyWithAlgorithm:  RNRSA.verifyWithAlgorithm.bind(RNRSA),
    verify64:  RNRSA.verify64.bind(RNRSA),
    verify64WithAlgorithm:  RNRSA.verify64WithAlgorithm.bind(RNRSA)
};

var RSAKeychain = {
    SHA256withRSA: RNRSAKeychain.getConstants().SHA256withRSA,
    SHA512withRSA: RNRSAKeychain.getConstants().SHA512withRSA,
    SHA1withRSA: RNRSAKeychain.getConstants().SHA1withRSA,
    SHA256withECDSA: RNRSAKeychain.getConstants().SHA256withECDSA,
    SHA512withECDSA: RNRSAKeychain.getConstants().SHA512withECDSA,
    SHA1withECDSA: RNRSAKeychain.getConstants().SHA1withECDSA,
    
    // Key generation functions
    generate: RNRSAKeychain.generate.bind(RNRSAKeychain),
    generateEC: RNRSAKeychain.generateEC.bind(RNRSAKeychain),
    generateCSR: RNRSAKeychain.generateCSR.bind(RNRSAKeychain),
    generateKeys: RNRSAKeychain.generateKeys.bind(RNRSAKeychain),
    generateCSRWithEC: RNRSAKeychain.generateCSRWithEC.bind(RNRSAKeychain),
    
    // Encryption/Decryption functions
    encrypt: RNRSAKeychain.encrypt.bind(RNRSAKeychain),
    decrypt: RNRSAKeychain.decrypt.bind(RNRSAKeychain),
    encrypt64: RNRSAKeychain.encrypt64.bind(RNRSAKeychain),
    decrypt64: RNRSAKeychain.decrypt64.bind(RNRSAKeychain),
    
    // Signing functions
    sign: RNRSAKeychain.sign.bind(RNRSAKeychain),
    signWithAlgorithm: RNRSAKeychain.signWithAlgorithm.bind(RNRSAKeychain),
    sign64WithAlgorithm: RNRSAKeychain.sign64WithAlgorithm.bind(RNRSAKeychain),
    
    // Verification functions
    verify: RNRSAKeychain.verify.bind(RNRSAKeychain),
    verifyWithAlgorithm: RNRSAKeychain.verifyWithAlgorithm.bind(RNRSAKeychain),
    verify64WithAlgorithm: RNRSAKeychain.verify64WithAlgorithm.bind(RNRSAKeychain),
    
    // Public key retrieval functions
    getPublicKey: RNRSAKeychain.getPublicKey.bind(RNRSAKeychain),
    getPublicKeyDER: RNRSAKeychain.getPublicKeyDER.bind(RNRSAKeychain),
    getPublicKeyRSA: RNRSAKeychain.getPublicKeyRSA.bind(RNRSAKeychain),
    
    deletePrivateKey: RNRSAKeychain.deletePrivateKey.bind(RNRSAKeychain)
};

export { RSA ,RSAKeychain};
export default RSA;
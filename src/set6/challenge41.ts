import {initRSA, modinv, RSAKey} from '../set5/challenge39';
import {CryptoBigNumber, sha256} from '../set5/utils';
import { BigNumber } from 'bignumber.js';

export interface RSAUnpaddedMessageRecoveryOracle {
    /**
     * Retrieve public key which oracle uses when encrypting
     */
    getPublicKey(): RSAKey;

    /**
     * Encrypt plaintext using public key mentioned above
     * @param plaintext
     */
    encrypt(plaintext: Buffer): Buffer;

    /**
     * Decrypt ciphertext using "unknown" private key.
     * Every ciphertext can be decrypted only once.
     *
     * @param ciphertext
     */
    decrypt(ciphertext: Buffer): Buffer;
}

export function initRSAUnpaddedMessageRecoveryOracle(): RSAUnpaddedMessageRecoveryOracle {
    const rsaFunctions = initRSA();
    const keyPair = rsaFunctions.generateKeyPair(3, 300);
    const previousHashes: {[key: string]: boolean} = {};

    function getPublicKey(): RSAKey {
        return keyPair.publicKey;
    }

    function encrypt(plaintext: Buffer): Buffer {
        return rsaFunctions.encryptMessage(plaintext, keyPair.publicKey);
    }

    function decrypt(ciphertext: Buffer): Buffer {
        const hash = sha256(ciphertext.toString('hex'));
        const hashHex = hash.toString('hex');
        if (previousHashes[hashHex]) {
            throw Error(`Ciphertext was already decrypted`);
        }
        const plaintext = rsaFunctions.decryptMessage(ciphertext, keyPair.privateKey);
        previousHashes[hashHex] = true;
        return plaintext;
    }

    return {
        getPublicKey,
        encrypt,
        decrypt
    };
}

export function decryptCiphertextUsingRSAUnpaddedMessageRecoveryOracle(
    ciphertext: Buffer,
    messageRecoveryOracle: RSAUnpaddedMessageRecoveryOracle
): Buffer {
    const publicKey = messageRecoveryOracle.getPublicKey();
    const bigRand = CryptoBigNumber.random();
    // Let S be a random number > 1 mod N. Doesn't matter what.
    const s = bigRand.times(publicKey.modulus)
        .plus(1)
        .integerValue(BigNumber.ROUND_DOWN);
    const invS = modinv(s, publicKey.modulus);
    // (S ^ E mod N)
    const sExponentiated = s.exponentiatedBy(publicKey.exponent, publicKey.modulus);
    const ciphertextNum = new CryptoBigNumber(ciphertext.toString('hex'), 16);
    const modifiedCiphertextNum = sExponentiated.times(ciphertextNum).modulo(publicKey.modulus);
    // C' = ((S ^ E mod N) C) mod N
    const modifiedCiphertext = Buffer.from(modifiedCiphertextNum.toString(16), 'hex');
    const modifiedPlaintext = messageRecoveryOracle.decrypt(modifiedCiphertext);
    const modifiedPlaintextNum = new CryptoBigNumber(modifiedPlaintext.toString('hex'), 16);
    // P = P' * invmod(S, N) mod N
    const plaintextNum = modifiedPlaintextNum.times(invS).modulo(publicKey.modulus);
    return Buffer.from(plaintextNum.toString(16), 'hex');
}
import * as crypto from 'crypto';
import {padBlockPKCS7} from './challenge9';
import {aes128EcbEncrypt, AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {aes128CbcEncrypt} from './challenge10';

export interface EncryptionOracle {

    /**
     * Encrypt plaintext using AES with randomly selected mode of encryption (ECB or CBC)
     * @param plaintext
     */
    encryptWithRandomKey(plaintext: Buffer): Buffer;
}

export class AESEncryptionOracle implements EncryptionOracle {

    // used for unit testing
    testEcbFlag: boolean | undefined;

    encryptWithRandomKey(plaintext: Buffer): Buffer {
        const key = AESEncryptionOracle.generateRandomKey();
        const randomPrefixBytesCount = Math.floor(Math.random() * 6) + 5;
        const randomSuffixBytesCount = Math.floor(Math.random() * 6) + 5;
        // Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext
        const randomPrefix = crypto.randomBytes(randomPrefixBytesCount);
        // ...and 5-10 bytes after the plaintext.
        const randomSuffix = crypto.randomBytes(randomSuffixBytesCount);
        const modifiedPlaintextLength = plaintext.length + randomPrefixBytesCount + randomSuffixBytesCount;
        const modifiedPlaintext = Buffer.alloc(modifiedPlaintextLength);
        randomPrefix.copy(modifiedPlaintext, 0);
        plaintext.copy(modifiedPlaintext, randomPrefix.length);
        randomSuffix.copy(modifiedPlaintext, plaintext.length + randomPrefix.length);
        const paddedPlaintext = padBlockPKCS7(modifiedPlaintext, AES_128_BLOCK_LENGTH_BYTES);
        let ciphertext: Buffer;
        // Now, have the function choose to encrypt under ECB 1/2 the time,
        // and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.
        const ecbFlag = typeof this.testEcbFlag === 'boolean' ? this.testEcbFlag : Math.round(Math.random());
        if (ecbFlag) {
            ciphertext = aes128EcbEncrypt(paddedPlaintext, key);
        } else {
            const iv = AESEncryptionOracle.generateRandomKey();
            ciphertext = aes128CbcEncrypt(paddedPlaintext, iv, key);
        }
        return ciphertext;
    }

    static generateRandomKey(): Buffer {
        return crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
    }

}
import * as crypto from 'crypto';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {aes128CtrDecrypt, aes128CtrEncrypt} from '../set3/challenge18';
import {padBlockPKCS7} from '../set2/challenge9';
import {unpadBlockPKCS7} from '../set2/challenge15';

const randomKey = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
const randomIV = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);

/**
 * Encrypt user input using randomly generated unknown key
 * @param userInput user input
 */
export function encryptData(userInput: string): Buffer {
    // 32 bytes
    const prefix = Buffer.from('comment1=cooking%20MCs;userdata=');
    // 42 bytes
    const suffix = Buffer.from(';comment2=%20like%20a%20pound%20of%20bacon');
    // escape user input
    const escapedSemiColons = userInput.replace(';', "';'");
    const escapedEquals = escapedSemiColons.replace('=', "'='");
    // concatenate it
    const concatenatedInput = Buffer.concat([prefix, Buffer.from(escapedEquals), suffix]);
    return aes128CtrEncrypt(padBlockPKCS7(concatenatedInput, AES_128_BLOCK_LENGTH_BYTES), randomKey, randomIV);
}

/**
 * Decrypt encrypted data and return true if user has admin role
 * @param encryptedData encrypted data
 */
export function isAdmin(encryptedData: Buffer): boolean {
    const plaintext = unpadBlockPKCS7(
        aes128CtrDecrypt(encryptedData, randomKey, randomIV),
        AES_128_BLOCK_LENGTH_BYTES
    );
    return plaintext.includes(';admin=true;');
}

/**
* Do a CTR bit flipping attack using encryption function which encrypts string provided by us
* and validation function which validates the result.
*
* Explanation:
* (c0 c1 c2 c3) - ciphertext bytes
* (p0 p1 p2 p3) - plaintext bytes
* (k0 k1 k2 k3) - keystream bytes
*
* c0 c1 c2 c3 = p0 p1 p2 0 XOR aes_ecb(k0 k1 k2 k3)
* in c3 we get the corresponding encrypted keystream byte
*
* p0 p1 p2 p3 = c0 c1 c2 c3 XOR aes_ecb(k0 k1 k2 k3)
* since we now the encrypted keystream byte we modify the ciphertext with aes_ecb(k0 k1 k2 k3)[3] XOR '='
* so that
* p3 = c3 XOR aes_ecb(k0 k1 k2 k3)
* p3 = aes_ecb(k0 k1 k2 k3)[3] XOR '=' XOR aes_ecb(k0 k1 k2 k3)
* p3 = '='
*
* @param encryptingFunction encrypting function using AES in CTR mode
* @param validationFunction validation function
*/
export function ctrFlipBits(
    encryptingFunction: (userInput: string) => Buffer,
    validationFunction: (ciphertext: Buffer) => boolean
): { input: string; ciphertext: Buffer } {
    const maliciousInput = '\x00admin\x00true';
    const positions = {
        ';': 2 * AES_128_BLOCK_LENGTH_BYTES,
        '=': 2 * AES_128_BLOCK_LENGTH_BYTES + 6
    };
    const ciphertext = encryptingFunction(maliciousInput);
    // ciphertext at this position contains the corresponding encrypted keystream byte
    ciphertext[positions[';']] = ciphertext[positions[';']] ^ 0x3b;
    // same as above
    ciphertext[positions['=']] = ciphertext[positions['=']] ^ 0x3d;
    if (validationFunction(ciphertext)) {
        return {
            input: maliciousInput,
            ciphertext
        }
    }
    throw Error(`Could not flip bits`);
}
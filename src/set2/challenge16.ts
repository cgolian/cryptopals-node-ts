import * as crypto from 'crypto';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {aes128CbcDecrypt, aes128CbcEncrypt} from './challenge10';
import {unpadBlockPKCS7} from './challenge15';
import {padBlockPKCS7} from './challenge9';

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
    return aes128CbcEncrypt(padBlockPKCS7(concatenatedInput, AES_128_BLOCK_LENGTH_BYTES), randomKey, randomIV);
}

/**
 * Decrypt encrypted data and return true if user has admin role
 * @param encryptedData encrypted data
 */
export function isAdmin(encryptedData: Buffer): boolean {
    const plaintext = unpadBlockPKCS7(
        aes128CbcDecrypt(encryptedData, randomKey, randomIV),
        AES_128_BLOCK_LENGTH_BYTES
    );
    return plaintext.includes(';admin=true;');
}

export type CbcBitFlippingResult = { input: string; ciphertext: Buffer };
export type CbcEncryptingFn = (userInput: string) => Buffer;
export type CbcValidationFn = (ciphertext: Buffer) => boolean;

/**
 * Do a CBC bit flipping attack using encryption function which encrypts string provided by us
 * and validation function which validates the result.
 *
 * @param encryptingFunction encrypting function using AES in CBC mode
 * @param validationFunction validation function
 */
export function cbcFlipBits(
    encryptingFunction: CbcEncryptingFn,
    validationFunction: CbcValidationFn
): CbcBitFlippingResult {
    // we want to replace ; and = with characters that will become AFTER 1-bit error ; and =
    // x01 is placeholder for ;
    // x02 is placeholder for =
    const maliciousInput = 'AAAAA\x01admin\x02true';
    // we have to add block AAAAAAAAAAAAAAAA - on this block we are doing the bit manipulations
    const plaintext = 'AAAAAAAAAAAAAAAA'.concat(maliciousInput);
    // sanitized input will look like this
    const ciphertext = encryptingFunction(plaintext);
    const semiColonPos = maliciousInput.indexOf('\x01');
    const equalSignPos = maliciousInput.indexOf('\x02');
    const positions = {
        ';': 2 * AES_128_BLOCK_LENGTH_BYTES + semiColonPos,
        '=': 2 * AES_128_BLOCK_LENGTH_BYTES + equalSignPos
    };
    const maliciousBuffer = Buffer.from(maliciousInput);
    // hex code of ; is 3B, in CBC decryption plaintext will be XORed with previous CT block - we want to get 3B in plaintext
    ciphertext[positions[';']] = ciphertext[positions[';']] ^ 0x3b ^ maliciousBuffer[semiColonPos];
    // hex code of = is 3D
    ciphertext[positions['=']] = ciphertext[positions['=']] ^ 0x3d ^ maliciousBuffer[equalSignPos];
    const validationResult = validationFunction(ciphertext);
    if (validationResult) {
        return { input: maliciousInput, ciphertext: ciphertext };
    } else {
        throw Error(`Could not flip bits`);
    }
}
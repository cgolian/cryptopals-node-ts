import * as crypto from 'crypto';
import {aes128EcbEncrypt, AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {isECBEncrypted} from '../set1/challenge8';
import {
    ConsistentKeyEncryptionOracle, decryptConsistentKeyEncryptionOracle
} from './challenge12';
import {AESEncryptionOracle} from './challenge11';
import {padBlockPKCS7} from './challenge9';

// I decided here to generate max one block random bytes
// Solution below should however work for any number
/**
 * Generate random number of random bytes
 */
function generateRandomBytes(): Buffer {
    // generate random count of random bytes
    const randomCount = Math.ceil(Math.random() * AES_128_BLOCK_LENGTH_BYTES);
    return crypto.randomBytes(randomCount);
}

export function consistentKeyRandomPrefixEncryptionOracle(): ConsistentKeyEncryptionOracle {
    const randomKey = AESEncryptionOracle.generateRandomKey();
    const randomBytes = generateRandomBytes();
    function encryptUsingConsistentKey(plaintext: Buffer): Buffer {
        const unknownBase64 = Buffer.from('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' +
            'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3' +
            'A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK', 'base64');

        const wrapped = Buffer.concat([randomBytes, plaintext, unknownBase64]);
        const padded = padBlockPKCS7(wrapped, AES_128_BLOCK_LENGTH_BYTES);
        return aes128EcbEncrypt(padded, randomKey);
    }
    return encryptUsingConsistentKey;
}

/**
 * Isolate random bytes by inserting as userInput incrementing number of same bytes (0x0 in this case).
 * Ciphertext then should contain two same output blocks - we don't care about content preceding them,
 * only about content succeeding them
 *
 * @param oracle encrypting with AES with ECB mode
 */
export function isolateRandomBytes(
    oracle: ConsistentKeyEncryptionOracle,
): Buffer | undefined {
    let isolatingInput;
    const inputByte = 0x0;
    // this should take at most three blocksizes of bytes
    for (let inputSize = 0;  inputSize < 3 * AES_128_BLOCK_LENGTH_BYTES; inputSize++) {
        // inserting incrementing number of same bytes
        const input = Buffer.alloc(inputSize, inputByte);
        const ciphertext = oracle(input);
        // wait until two ciphertext blocks are the same -> we don't care about the ones before them,
        // we only care about the blocks which come nenxt
        const { result } = isECBEncrypted(ciphertext.toString('hex'));
        // i == 0 would have meant that plaintext itself contains repeating blocks
        if (result && inputSize != 0) {
            isolatingInput = input.slice(0, input.length - AES_128_BLOCK_LENGTH_BYTES);
            break;
        }
    }
    return isolatingInput;
}

// Return oracle which will behave as the previous one - meaning it will encrypt only userInput || unknown string
export function initOracleWithoutRandomPrefix(
    oracle: ConsistentKeyEncryptionOracle,
    isolatingInput: Buffer,
): ConsistentKeyEncryptionOracle {
    return function(plaintext: Buffer): Buffer {
        const concatenatedInput = Buffer.alloc(
            isolatingInput.length + plaintext.length
        );
        isolatingInput.copy(concatenatedInput);
        plaintext.copy(concatenatedInput, isolatingInput.length);
        const ciphertext = oracle(concatenatedInput);
        // strip block with random bytes and isolating input
        return ciphertext.slice(2 * AES_128_BLOCK_LENGTH_BYTES, ciphertext.length);
    };
}

export function decryptConsistentKeyRandomPrefixEncryptionOracle(
    oracle: ConsistentKeyEncryptionOracle
): Buffer {
    // get user input which will isolate random bytes
    const isolatingInput = isolateRandomBytes(oracle);
    if (!isolatingInput) {
        throw Error(`Isolating input could not be found`);
    }
    // redefine oracle function
    const oracleWithoutRandomBytes = initOracleWithoutRandomPrefix(
        oracle,
        isolatingInput
    );
    return decryptConsistentKeyEncryptionOracle(oracleWithoutRandomBytes);
}
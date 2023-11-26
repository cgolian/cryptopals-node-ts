import {AESEncryptionOracle} from './challenge11';
import {padBlockPKCS7} from './challenge9';
import {aes128EcbEncrypt, AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';

export type ConsistentKeyEncryptionOracle = (plaintext: Buffer) => Buffer;

type PlaintextByte = number;
interface LastByteDictionary {
    [ciphertextBlockHex: string]: PlaintextByte; // k: ciphertext
}

export function consistentKeyEncryptionOracle(): ConsistentKeyEncryptionOracle {
    const randomKey = AESEncryptionOracle.generateRandomKey();
    function encryptUsingConsistentKey(plaintext: Buffer): Buffer {
        const unknownBase64 = Buffer.from('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' +
            'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3' +
            'A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK', 'base64');
        const appended = Buffer.concat([plaintext, unknownBase64]);
        const padded = padBlockPKCS7(appended, AES_128_BLOCK_LENGTH_BYTES);
        return aes128EcbEncrypt(padded, randomKey);
    }
    return encryptUsingConsistentKey;
}

const INPUT_PLACEHOLDER = 'A';

/**
 * Discover block size of an encryption function by feeding it bytes and looking for repeating ciphertext blocks.
 * @param encryptionOracle encryption oracle function
 */
export function discoverBlockSize(
    encryptionOracle: ConsistentKeyEncryptionOracle
): number {
    let blockSize = 0;
    let prevCiphertext = encryptionOracle(Buffer.from(''));
    let ciphertext;
    let strLength = 1;
    let blockSizeFound = false;
    while (!blockSizeFound) {
        ciphertext = encryptionOracle(Buffer.alloc(strLength, INPUT_PLACEHOLDER));
        if (ciphertext.length != prevCiphertext.length) {
            blockSize = ciphertext.length - prevCiphertext.length;
            blockSizeFound = true;
        } else {
            strLength++;
            prevCiphertext = ciphertext;
        }
    }
    return blockSize;
}

export function createLastByteDictionaryForBlockAndByte(
    encryptionOracle: ConsistentKeyEncryptionOracle,
    knownPlaintext: Buffer,
    blockIdx: number,
    byteIdx: number,
): LastByteDictionary {
    if (byteIdx >= AES_128_BLOCK_LENGTH_BYTES) {
        throw Error(`Invalid byte index`);
    }
    // set up input block
    const inputBlock = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES, INPUT_PLACEHOLDER);
    if (blockIdx === 0) {
        if (byteIdx > 0) {
            knownPlaintext.copy(inputBlock, AES_128_BLOCK_LENGTH_BYTES - byteIdx - 1, 0, byteIdx);
        }
    } else {
        knownPlaintext.copy(
            inputBlock,
            0,
            (blockIdx - 1) * AES_128_BLOCK_LENGTH_BYTES + byteIdx + 1,
            (blockIdx) * AES_128_BLOCK_LENGTH_BYTES + byteIdx)
    }
    const lastByteDictionary: LastByteDictionary = {};
    let ciphertext;
    let firstCiphertextBlock;
    // fill the dictionary
    for (let i = 0; i < 256; i++) {
        inputBlock[AES_128_BLOCK_LENGTH_BYTES - 1] = i;
        ciphertext = encryptionOracle(inputBlock);
        firstCiphertextBlock = ciphertext.slice(0, AES_128_BLOCK_LENGTH_BYTES);
        lastByteDictionary[firstCiphertextBlock.toString('hex')] = i;
    }
    return lastByteDictionary;
}

export function decryptConsistentKeyEncryptionOracle(
    encryptionOracle: ConsistentKeyEncryptionOracle,
): Buffer {
    let ciphertext = encryptionOracle(Buffer.from(''));
    const ciphertextBlocks = ciphertext.length / AES_128_BLOCK_LENGTH_BYTES;
    const plaintext = Buffer.alloc(ciphertext.length);
    let dictionary;
    const craftedInputs = [];
    // craft 'short' inputs
    for (let i = 1; i <= AES_128_BLOCK_LENGTH_BYTES; i++) {
        craftedInputs.push(Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES - i, INPUT_PLACEHOLDER));
    }
    // decrypt ciphertext byte by byte
    let ciphertextBlock;
    for (let blockIdx = 0; blockIdx < ciphertextBlocks; blockIdx++) {
        for (let byteIdx = 0; byteIdx < AES_128_BLOCK_LENGTH_BYTES; byteIdx++) {
            dictionary = createLastByteDictionaryForBlockAndByte(encryptionOracle, plaintext, blockIdx, byteIdx);
            ciphertext = encryptionOracle(craftedInputs[byteIdx]);
            // find corresponding block
            ciphertextBlock = ciphertext.slice(blockIdx * AES_128_BLOCK_LENGTH_BYTES, (blockIdx + 1) * AES_128_BLOCK_LENGTH_BYTES);
            plaintext[blockIdx * AES_128_BLOCK_LENGTH_BYTES + byteIdx] = dictionary[ciphertextBlock.toString('hex')];
        }
    }
    return plaintext;
}
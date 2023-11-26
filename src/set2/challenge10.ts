import {
    aes128ComputeSubkeys, aes128DecryptBlock, aes128EncryptBlock,
    AES_128_BLOCK_LENGTH_BYTES,
    splitTextIntoBlocks,
    validateKeyLength,
    validateTextLength
} from '../set1/challenge7';
import {XORBitArrays} from '../set1/challenge2';
import {BitArray} from '../set1/challenge1';

/**
 * Encrypt plaintext with key using AES-128-CBC
 * @param plaintext
 * @param iv initialization vector
 * @param key
 */
export function aes128CbcEncrypt(plaintext: Buffer, iv: Buffer, key: Buffer): Buffer {
    validateTextLength(plaintext);
    validateKeyLength(key);
    validateKeyLength(iv);
    const plaintextBlocks = splitTextIntoBlocks(plaintext, AES_128_BLOCK_LENGTH_BYTES);
    const ciphertextBlocks: Buffer[] = [];
    const subkeys = aes128ComputeSubkeys(key);
    let prevCiphertext = iv;
    plaintextBlocks.forEach((plaintextBlock) => {
        const xord = XORBitArrays(BitArray.fromBuffer(plaintextBlock), BitArray.fromBuffer(prevCiphertext));
        prevCiphertext = aes128EncryptBlock(BitArray.toBuffer(xord), subkeys);
        ciphertextBlocks.push(prevCiphertext);
    });
    const ciphertext = Buffer.alloc(plaintext.length);
    ciphertextBlocks.forEach((ciphertextBlock, idx) => {
        ciphertextBlock.copy(ciphertext, idx * AES_128_BLOCK_LENGTH_BYTES);
    });
    return ciphertext;
}

/**
 * Decrypt ciphertext with key using AES-128-CBC
 * @param ciphertext
 * @param iv initialization vector
 * @param key
 */
export function aes128CbcDecrypt(ciphertext: Buffer, iv: Buffer, key: Buffer): Buffer {
    validateTextLength(ciphertext);
    validateKeyLength(key);
    validateKeyLength(iv);
    const ciphertextBlocks = splitTextIntoBlocks(ciphertext, AES_128_BLOCK_LENGTH_BYTES);
    const plaintextBlocks: Buffer[] = [];
    const subkeys = aes128ComputeSubkeys(key);
    let prevCiphertext = iv;
    ciphertextBlocks.forEach((ciphertextBlock) => {
        const decrypted = aes128DecryptBlock(ciphertextBlock, subkeys);
        const xord = XORBitArrays(BitArray.fromBuffer(decrypted), BitArray.fromBuffer(prevCiphertext));
        plaintextBlocks.push(BitArray.toBuffer(xord));
        prevCiphertext = ciphertextBlock;
    });
    const plaintext = Buffer.alloc(ciphertext.length);
    plaintextBlocks.forEach((plaintextBlock, idx) => {
        plaintextBlock.copy(plaintext, idx * AES_128_BLOCK_LENGTH_BYTES);
    });
    return plaintext;
}
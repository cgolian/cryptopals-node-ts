import * as crypto from 'crypto';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {unpadBlockPKCS7} from '../set2/challenge15';
import {aes128CbcDecrypt, aes128CbcEncrypt} from '../set2/challenge10';
import {padBlockPKCS7} from '../set2/challenge9';
import {splitIntoBlocks} from '../set1/challenge6';

type EncryptionOracleCBC = () => { ciphertext: Buffer; iv: Buffer };
type PaddingOracleCBC = (ciphertext: Buffer) => boolean;

type EncryptionFunctionPaddingOraclePair = {
    encryptCBC: EncryptionOracleCBC;
    paddingOracle: PaddingOracleCBC;
}

export function createEncryptionFunctionAndPaddingOraclePair(): EncryptionFunctionPaddingOraclePair {
    const possiblePlaintexts = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ];
    const randomAESKey = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
    const randomIV = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);

    /**
     * Encrypt plaintext randomly selected from the ones above and encrypt it using AES in CBC mode.
     */
    function encryptCBC(): {
        ciphertext: Buffer;
        iv: Buffer;
    } {
        const plaintextNr = Math.ceil(Math.random() * 9);
        const selectedPlaintext = Buffer.from(possiblePlaintexts[plaintextNr], 'base64');
        const paddedPlaintext = padBlockPKCS7(selectedPlaintext, AES_128_BLOCK_LENGTH_BYTES);
        const ciphertext = aes128CbcEncrypt(paddedPlaintext, randomIV, randomAESKey);
        return { ciphertext, iv: randomIV };
    }

    /**
     * Decrypt ciphertext and validate its padding
     * @param ciphertext ciphertext
     */
    function paddingOracle(ciphertext: Buffer): boolean {
        const plaintext = aes128CbcDecrypt(ciphertext, randomIV, randomAESKey);
        try {
            unpadBlockPKCS7(plaintext, AES_128_BLOCK_LENGTH_BYTES);
            return true;
        } catch (err) {
            return false;
        }
    }
    return { encryptCBC, paddingOracle };
}

function paddingOracleDecryptCiphertextByte(
    byteIdx: number,
    prevCiphertextBlock: Buffer,
    ciphertextBlock: Buffer,
    decryptedPlaintextBlock: Buffer,
    paddingOracleCBC: PaddingOracleCBC
): number {
    const oracleInput = Buffer.concat([prevCiphertextBlock, ciphertextBlock]);
    const paddingByte = AES_128_BLOCK_LENGTH_BYTES - byteIdx;
    for (let paddingByteIdx = byteIdx + 1; paddingByteIdx < AES_128_BLOCK_LENGTH_BYTES; paddingByteIdx++) {
        oracleInput[paddingByteIdx] = oracleInput[paddingByteIdx] ^ decryptedPlaintextBlock[paddingByteIdx] ^ paddingByte;
    }
    for (let byte = 0; byte < 256; byte++) {
        oracleInput[byteIdx] = byte;
        if (paddingOracleCBC(oracleInput)) {
            return oracleInput[byteIdx] ^ prevCiphertextBlock[byteIdx] ^ paddingByte;
        }
    }
    throw Error(`Could not decrypt byte`);
}

function paddingOracleDecryptLastCBCCiphertextBlock(
    prevCiphertextBlock: Buffer,
    ciphertextBlock: Buffer,
    paddingOracleCBC: PaddingOracleCBC
): Buffer {
    const oracleInput = Buffer.concat([prevCiphertextBlock, ciphertextBlock]);
    const decrypted = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES);
    if (paddingOracleCBC(oracleInput)) {
        let paddingByte;
        // find the 'padding' byte
        for (let i = AES_128_BLOCK_LENGTH_BYTES - 2; i >= 0; i--) {
            oracleInput[i] = 0xFF;
            const result = paddingOracleCBC(oracleInput);
            if (result) {
                // one byte is scrambled yet input was validated - it means we detected the padding byte
                paddingByte = AES_128_BLOCK_LENGTH_BYTES - i - 1;
                decrypted.fill(paddingByte, i + 1);
                break;
            }
            oracleInput[i] = prevCiphertextBlock[i];
        }
        if (!paddingByte) {
            paddingByte = AES_128_BLOCK_LENGTH_BYTES;
            decrypted.fill(paddingByte);
        } else {
            // decrypt rest of the block
            for (let byteIdx = AES_128_BLOCK_LENGTH_BYTES - paddingByte; byteIdx >= 0; byteIdx--) {
                decrypted[byteIdx] = paddingOracleDecryptCiphertextByte(
                    byteIdx, prevCiphertextBlock, ciphertextBlock, decrypted, paddingOracleCBC);
            }
        }
        return decrypted;
    } else {
        throw Error(`Could not decrypt last block`);
    }
}

function paddingOracleDecryptCBCCiphertextBlock(
    prevCiphertextBlock: Buffer,
    ciphertextBlock: Buffer,
    paddingOracleCBC: PaddingOracleCBC
): Buffer {
    const decrypted = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES);
    for (let byteIdx = AES_128_BLOCK_LENGTH_BYTES - 1; byteIdx >= 0; byteIdx--) {
        decrypted[byteIdx] = paddingOracleDecryptCiphertextByte(byteIdx, prevCiphertextBlock, ciphertextBlock,
            decrypted, paddingOracleCBC);
    }
    return decrypted;
}

export function paddingOracleDecryptCBCCiphertext(
    ciphertext: Buffer,
    iv: Buffer,
    paddingOracle: PaddingOracleCBC
): Buffer {
    const blocks = [iv, ...splitIntoBlocks(ciphertext, AES_128_BLOCK_LENGTH_BYTES)];
    const plaintext = Buffer.alloc(ciphertext.length);
    let decryptedBlock;
    for (let i = 1; i < blocks.length - 1; i++) {
        decryptedBlock = paddingOracleDecryptCBCCiphertextBlock(blocks[i-1], blocks[i], paddingOracle);
        decryptedBlock.copy(plaintext, (i-1) * AES_128_BLOCK_LENGTH_BYTES);
    }
    decryptedBlock = paddingOracleDecryptLastCBCCiphertextBlock(blocks[blocks.length - 2], blocks[blocks.length - 1],
        paddingOracle);
    decryptedBlock.copy(plaintext, (blocks.length - 2) * AES_128_BLOCK_LENGTH_BYTES);
    return plaintext;
}
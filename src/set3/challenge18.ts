import {splitIntoBlocks} from '../set1/challenge6';
import {aes128EcbEncrypt, AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {BitArray} from '../set1/challenge1';
import {XORBitArrays} from '../set1/challenge2';

export enum NonceType {
    LITTLE_ENDIAN_UNSIGNED
}

export enum CounterType {
    LITTLE_ENDIAN_BLOCK_COUNT
}

export type CtrFormat = {
    nonce: { size: number; type: NonceType};
    counter: { size: number; type: CounterType };
};

function applyAes128CtrCounterLENonceLE(
    text: Buffer,
    key: Buffer,
    counter: Buffer,
    nonce: Buffer,
    format: CtrFormat
): Buffer {
    const result = Buffer.alloc(text.length);

    const nonceWithCounter = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES);
    // fill with LE nonce
    nonce.copy(nonceWithCounter, 0, format.nonce.size);

    let counterValue = 0;
    const blocks = splitIntoBlocks(text, AES_128_BLOCK_LENGTH_BYTES);
    blocks.forEach((block: Buffer, blockIdx: number) => {
        // update with incremented counter
        counter.copy(nonceWithCounter, format.nonce.size);
        // encrypt ( nonce || counter buffer) with provided key
        let keystream = aes128EcbEncrypt(nonceWithCounter, key);
        // trim keystream to match block size
        keystream = keystream.slice(0, block.length);
        // XOR the result with plaintext/ciphertext block
        const resultingBlock = BitArray.toBuffer(XORBitArrays(BitArray.fromBuffer(keystream), BitArray.fromBuffer(block)));
        resultingBlock.copy(result, blockIdx * AES_128_BLOCK_LENGTH_BYTES);
        // increment counter & store its new value
        counter.writeInt32LE(++counterValue);
    });
    return result;
}

/**
 * Encrypt key using AES-128 CTR mode.
 * @param plaintext text to be encrypted.
 * @param key key to be used
 * @param nonce nonce
 * @param format type of the nonce and counter used
 */
export function aes128CtrEncrypt(
    plaintext: Buffer,
    key: Buffer,
    nonce: Buffer,
    format: CtrFormat = {
        nonce: { type: NonceType.LITTLE_ENDIAN_UNSIGNED, size: 8},
        counter: { type: CounterType.LITTLE_ENDIAN_BLOCK_COUNT, size: 8}
    }
): Buffer {
    if (format.counter.type === CounterType.LITTLE_ENDIAN_BLOCK_COUNT
        && format.nonce.type === NonceType.LITTLE_ENDIAN_UNSIGNED) {
        const counter = Buffer.alloc(format.counter.size);
        return applyAes128CtrCounterLENonceLE(plaintext, key, counter, nonce, format);
    } else {
        throw Error(`Not implemented`);
    }
}

/**
 * Decrypt key using AES-128 CTR mode.
 * @param ciphertext text to be decrypted.
 * @param key key to be used
 * @param nonce nonce
 * @param format type of the nonce and counter used
 */
export function aes128CtrDecrypt(
    ciphertext: Buffer,
    key: Buffer,
    nonce: Buffer,
    format: CtrFormat = {
        nonce: { type: NonceType.LITTLE_ENDIAN_UNSIGNED, size: 8},
        counter: { type: CounterType.LITTLE_ENDIAN_BLOCK_COUNT, size: 8}
    }
): Buffer {
    if (format.counter.type === CounterType.LITTLE_ENDIAN_BLOCK_COUNT
        && format.nonce.type === NonceType.LITTLE_ENDIAN_UNSIGNED) {
        const counter = Buffer.alloc(format.counter.size);
        return applyAes128CtrCounterLENonceLE(ciphertext, key, counter, nonce, format);
    } else {
        throw Error(`Not implemented`);
    }
}

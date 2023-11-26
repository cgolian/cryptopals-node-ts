import {XORBitArrays} from './challenge2';
import {BitArray} from './challenge1';

export function createXORKey(phrase: Buffer, length: number): Buffer {
    // make key as long as input
    const extendedKey = Buffer.alloc(length);
    phrase.copy(extendedKey, 0);
    for (let idx = phrase.length; idx < extendedKey.length; idx++) {
        extendedKey[idx] = phrase[idx % phrase.length];
    }
    return extendedKey;
}

/**
 * XOR input with provided key and return the result
 * @param input input buffer
 * @param key key buffer
 */
export function encryptWithXOR(input: Buffer, key: Buffer): Buffer {
    if (input.length < key.length) {
        throw Error(`Input too short`);
    }
    const extendedKey = createXORKey(key, input.length);
    const resultingBitArray = XORBitArrays(BitArray.fromBuffer(extendedKey), BitArray.fromBuffer(input));
    return BitArray.toBuffer(resultingBitArray);
}
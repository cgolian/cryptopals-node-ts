import {mt19937rng, SeededRng} from './challenge21';
import {XORBitArrays} from '../set1/challenge2';
import {BitArray} from '../set1/challenge1';
import * as crypto from 'crypto';

export function generateKeystreamFromRng(bufferLength: number, rand: SeededRng): Buffer {
    const keystream = Buffer.alloc(bufferLength);
    const bufferBits = bufferLength * 8;
    const numOfRandCalls = Math.ceil(bufferBits / 32);
    let generated;
    let i = 0;
    for (; i < numOfRandCalls; i++) {
        generated = rand();
        if (4*i < bufferLength) keystream[4*i]         = (generated & 0xF000) >> 12;
        if (4*i + 1 < bufferLength) keystream[4*i + 1] = (generated & 0xF00) >> 8;
        if (4*i + 2 < bufferLength) keystream[4*i + 2] = (generated & 0xF0) >> 4;
        if (4*i + 3 < bufferLength) keystream[4*i + 3] = generated & 0xF;
    }
    return keystream;
}

/**
 * Encrypt plaintext with MT19937 RNG
 * @param plaintext
 * @param seed
 */
export function encryptWithMt19937(plaintext: Buffer, seed: number): Buffer {
    const rand = mt19937rng(seed, 32);
    const keystream = generateKeystreamFromRng(plaintext.length, rand);
    return BitArray.toBuffer(XORBitArrays(BitArray.fromBuffer(plaintext), BitArray.fromBuffer(keystream)));
}

/**
 * Decrypt ciphertext with MT19937 RNG
 * @param ciphertext
 * @param seed
 */
export function decryptWithMt19937(ciphertext: Buffer, seed: number): Buffer {
    const rand = mt19937rng(seed, 32);
    const keystream = generateKeystreamFromRng(ciphertext.length, rand);
    return BitArray.toBuffer(XORBitArrays(BitArray.fromBuffer(ciphertext), BitArray.fromBuffer(keystream)));
}

export function encryptKnownPlaintextWithRandomSeed(plaintext: Buffer): { ciphertext: Buffer; seed: number } {
    const randomSeed = crypto.randomBytes(2).readUInt16LE();
    const randomCount = Math.random() * (10 - 1) + 1;
    const random = crypto.randomBytes(randomCount);
    return { ciphertext: encryptWithMt19937(Buffer.concat([random, plaintext]), randomSeed), seed: randomSeed } ;
}

export function extractSeed(
    knownPlaintext: Buffer,
    ciphertext: Buffer,
): number {
    let result: Buffer;
    for (let i = 0; i < 65536; i++) {
        result = decryptWithMt19937(ciphertext, i);
        if (result.includes(knownPlaintext)) {
            return i;
        }
    }
    throw Error(`Could not extract random seed`);
}

export function generatePasswordToken(): Buffer {
    const cur = Date.now();
    const token = Buffer.from(`token=value&expires=${cur}`);
    return encryptWithMt19937(token, cur);
}

export function isTokenMt19937EncryptedSeededWithTimestamp(
    encryptedToken: Buffer
): boolean {
    const thirtySecondsAgo = Date.now() - 30 * 1000;
    const curDate = Date.now();
    let plaintext: Buffer;
    for (let i = thirtySecondsAgo; i < curDate; i++) {
        plaintext = decryptWithMt19937(encryptedToken, i);
        if (plaintext.includes(i.toString(10))) return true;
    }
    return false;
}
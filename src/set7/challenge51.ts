import * as crypto from 'crypto';
import * as zlib from 'zlib';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';

export interface CompressionOracle {
    /**
     * Return length of compressed ciphertext
     * @param payload payload to be compressed
     */
    getCiphertextLength(payload: Buffer): number;
}

export function initPrepareRequest(sessionKey: Buffer): (payload: Buffer) => Buffer {
    function prepareRequest(msgPayload: Buffer): Buffer {
         const msgHeader = Buffer.from(`POST / HTTP/1.1\n` +
        `Host: hapless.com\nCookie: sessionid=${sessionKey.toString()}\n` +
        `Content-Length: ${msgPayload.length}\n`);
         return Buffer.concat([msgHeader, msgPayload]);
    }
    return prepareRequest;
}

type CipherType = 'aes-128-cbc' | 'aes-128-ctr';
export function initCompressionOracle(
    cipherType: CipherType,
    prepareRequest: (payload: Buffer) => Buffer
): CompressionOracle {
    function getCiphertextLength(payload: Buffer): number {
        const randomKey = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
        const randomIV = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
        const cipher = crypto.createCipheriv(cipherType, randomKey, randomIV);
        if (cipherType === 'aes-128-ctr') cipher.setAutoPadding(false);
        const request = prepareRequest(payload);
        const compressed = zlib.deflateRawSync(request);
        let encrypted = cipher.update(compressed);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return encrypted.length;
    }

    return {
        getCiphertextLength
    }
}

export function recoverStreamCipherEncryptedSessionKeyUsingCompressionOracle(
    sessionKeyLength: number,
    compressionOracle: CompressionOracle
): Buffer {
    const base64Chars = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');
    const decryptedKey = Buffer.alloc(sessionKeyLength);
    const baseInput = Buffer.from(` sessionid=`), star = Buffer.from('*');
    let baseLength, curLength, cur, input, firstStarIdx, secondStarIdx;
    for (let sIdx = 0; sIdx < sessionKeyLength; sIdx++) {
        cur = -1;
        input = Buffer.concat([baseInput, decryptedKey.slice(0, sIdx), star]);
        firstStarIdx = input.length - 1;
        input[input.length - 1] = 0x2A; // printable non-base64 char
        // we duplicate the payload - should compress better and help us exclude false positives
        baseLength = compressionOracle.getCiphertextLength(Buffer.concat([input, input]));
        secondStarIdx = 2 * input.length - 1;
        for (let cIdx = 0; cIdx < base64Chars.length; cIdx++) {
            input[firstStarIdx] = base64Chars[cIdx];
            input[secondStarIdx] = base64Chars[cIdx];
            curLength = compressionOracle.getCiphertextLength(Buffer.concat([input, input]));
            if (curLength < baseLength) {
                baseLength = curLength;
                cur = base64Chars[cIdx];
            }
        }
        if (cur === -1) throw Error(`Could not decrypt character at ${sIdx}`);
        decryptedKey[sIdx] = cur;
    }
    return decryptedKey;
}

function constructCompressingInput(
    decryptedKey: Buffer,
    prepareReq: (payload: Buffer) => Buffer
): Buffer {
    let input = Buffer.concat([Buffer.from(` sessionid=`), decryptedKey, Buffer.from(`*`)]);
    let req = prepareReq(input), compressed = zlib.deflateRawSync(req);
    let nrOfPaddingBytes = compressed.length % AES_128_BLOCK_LENGTH_BYTES;
    while (nrOfPaddingBytes != 0) {
        input = Buffer.concat([crypto.randomBytes(1), input]);
        req = prepareReq(input);
        compressed = zlib.deflateRawSync(req);
        nrOfPaddingBytes = compressed.length % AES_128_BLOCK_LENGTH_BYTES;
    }
    return input;
}

export function recoverBlockCipherEncryptedSessionKeyUsingCompressionOracle(
    sessionKeyLength: number,
    prepareReq: (payload: Buffer) => Buffer,
    compressionOracle: CompressionOracle
): Buffer {
    const base64Chars = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');
    const decryptedKey = Buffer.alloc(sessionKeyLength);
    let input, cur, baseLength, curLength;
    for (let sIdx = 0; sIdx < sessionKeyLength; sIdx++) {
        input = constructCompressingInput(decryptedKey.slice(0, sIdx), prepareReq);
        baseLength = compressionOracle.getCiphertextLength(input);
        cur = -1;
        for (let cIdx = 0; cIdx < base64Chars.length; cIdx++) {
            input[input.length - 1] = base64Chars[cIdx];
            curLength = compressionOracle.getCiphertextLength(input);
            if (curLength < baseLength) {
                baseLength = curLength;
                cur = base64Chars[cIdx];
            }
        }
        if (cur === -1) throw Error(`Could not decrypt character at position ${sIdx}`);
        decryptedKey[sIdx] = cur;
    }
    return decryptedKey;
}
import * as crypto from 'crypto';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';

export interface RC4EncryptionOracle {
    /**
     * Concatenate plaintext with hidden cookie & encrypt the result with a random key
     * @param plaintext
     */
    encryptWithRandomKey(plaintext: Buffer): Buffer;
}

export function initRC4EncryptionOracle(): RC4EncryptionOracle {
    const cookie = Buffer.from('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F', 'base64');

    function encryptWithRandomKey(plaintext: Buffer): Buffer {
        const randomKey = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
        const cipher = crypto.createCipheriv('rc4', randomKey, null);
        let encrypted = cipher.update(Buffer.concat([plaintext, cookie]));
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return encrypted;
    }

    return  {
        encryptWithRandomKey,
    }
}

/*
biases:
Z_16 (15 if 0 indexed) ~ 0xF0
Z_32 (31 if 0 indexed) ~ 0xE0

RC4: ciphertext = plaintext XOR keystream byte
     plaintext = ciphertext XOR keystream byte
 */
function decryptIthAndIPlusSixteenthByte(
    i: number,
    encryptionOracle: RC4EncryptionOracle
): { p16: number; p32: number } {
    const numOfCalls = Math.pow(2, 24);
    const z16byteCount: Map<number, number> = new Map<number, number>();
    const z32byteCount: Map<number, number> = new Map<number, number>();
    // initialize maps
    for (let i = 0; i < 256; i++) {
        z16byteCount.set(i, 0);
        z32byteCount.set(i, 0);
    }
    // make numOfCalls calls to the encryption oracle & store corresponding ciphertext bytes
    const plaintext = Buffer.alloc(15 - i);
    let ciphertext: Buffer, c16: number, c32: number, p16 = -1, p32 = -1;
    for (let j = 0; j < numOfCalls; j++) {
        ciphertext = encryptionOracle.encryptWithRandomKey(plaintext);
        c16 = ciphertext[15];
        c32 = ciphertext[31];
        z16byteCount.set(c16, (z16byteCount.get(c16) as number) + 1);
        z32byteCount.set(c32, (z32byteCount.get(c32) as number) + 1);
        if (j % 1_000_000 === 0) {
            console.log(`Iteration nr ${j}`);
        }
    }
    // infer plaintext byte from the ciphertext byte with the highest occurrence
    let maxP16Count = 0, maxP32Count = 0;
    z16byteCount.forEach((count, byte) => {
        if (count > maxP16Count) {
            maxP16Count = count;
            p16 = byte ^ 0xF0;
       }
    });
    z32byteCount.forEach((count, byte) => {
        if (count > maxP32Count) {
            maxP32Count = count;
            p32 = byte ^ 0xE0;
        }
    });
    return { p16, p32 };
}

// BE SURE TO DRINK YOUR OVALTINE
function decryptRC4EncryptedCookie(
    encryptionOracle: RC4EncryptionOracle,
    cookieLength: number
): Buffer {
    const decrypted = Buffer.alloc(cookieLength);
    let decryptedBytes: { p16: number; p32: number};
    for (let i = 0; i < 16; i++) {
        decryptedBytes = decryptIthAndIPlusSixteenthByte(i, encryptionOracle);
        if (decryptedBytes.p16 !== -1) decrypted[i] = decryptedBytes.p16;
        if (decryptedBytes.p32 !== -1) decrypted[i + 16] = decryptedBytes.p32;
        console.log(decrypted);
        console.log(decrypted.toString());
    }
    return decrypted;
}
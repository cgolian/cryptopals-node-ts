import * as fs from 'fs';
import {aes128CbcDecrypt, aes128CbcEncrypt} from './challenge10';

describe('Challenge 10', () => {
    let fileCiphertext: Buffer;

    beforeEach(() => {
        const fileContents = fs.readFileSync('./src/set2/10.txt', 'utf8');
        fileCiphertext = Buffer.from(fileContents, 'base64');
    });

    describe('AES CBC encryption', () => {
        it('should encrypt plaintext', () => {
            const iv = Buffer.alloc(16, 0x0);
            const key = Buffer.from('YELLOW SUBMARINE');

            const plaintext = aes128CbcDecrypt(fileCiphertext, iv, key);
            const result = aes128CbcEncrypt(plaintext, iv, key); // TEST

            expect(fileCiphertext).toEqual(result);
        });
    });

    describe('AES CBC decryption', () => {
        it('should decrypt ciphertext', () => {
            const iv = Buffer.alloc(16, 0x0);
            const key = Buffer.from('YELLOW SUBMARINE');

            const result = aes128CbcDecrypt(fileCiphertext, iv, key); // TEST

            expect(result.includes('Vanilla\'s on the mike, man I\'m not lazy.')).toBe(true);
        });
    });
});
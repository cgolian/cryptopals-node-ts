import {aes128CtrEncrypt} from '../set3/challenge18';
import {Aes128CtrEditOracle, initAes128CtrEditOracle, recoverPlaintextUsingAesCtrEditOracle} from './challenge25';
import * as fs from 'fs';
import * as crypto from 'crypto';
import {aes128EcbDecrypt, AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';

describe('Challenge 25', () => {
    describe('edit function', () => {
        let key: Buffer;
        let nonce: Buffer;
        let plaintext: Buffer;
        let ciphertext: Buffer;
        let expectedCiphertext: Buffer;
        let aes128CtrEditOracle: Aes128CtrEditOracle;

        beforeEach(() => {
            plaintext = Buffer.from('Where dey looked down me pants, look up me bottom, so');
            key = Buffer.from('YELLOW SUBMARINE');
            nonce = Buffer.from([0x2, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1]);
            const modifiedPlaintext = Buffer.from('Where dey looked down me shirt, look up me bottom, so');
            ciphertext = aes128CtrEncrypt(plaintext, key, nonce);
            expectedCiphertext = aes128CtrEncrypt(modifiedPlaintext, key, nonce);
            aes128CtrEditOracle = initAes128CtrEditOracle(key, nonce);
        });

        it('should not edit plaintext at negative offset', () => {
            expect(() => aes128CtrEditOracle.edit(ciphertext, -1, Buffer.from('shirt'))).toThrow(Error); // TEST
        });

        it('should not edit plaintext at "out of bounds" offset', () => {
            expect(() => aes128CtrEditOracle.edit(ciphertext,  1024, Buffer.from('shirt'))).toThrow(Error); // TEST
        });

        it('should edit plaintext', () => {
            const result = aes128CtrEditOracle.edit(ciphertext, 25, Buffer.from('shirt')); // TEST
            expect(result).toEqual(expectedCiphertext);
        });
    });

    xdescribe('recover plaintext using edit oracle', () => {
        let ciphertext: Buffer;
        let editOracle: Aes128CtrEditOracle;

        beforeEach(() => {
            const contents = fs.readFileSync(
                './src/set4/25.txt',
                'utf8'
            );
            const plaintext = aes128EcbDecrypt(Buffer.from(contents, 'base64'), Buffer.from('YELLOW SUBMARINE'));

            const randomKey = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
            const randomNonce = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES / 2);
            editOracle = initAes128CtrEditOracle(randomKey, randomNonce);
            ciphertext = aes128CtrEncrypt(
                plaintext,
                randomKey,
                randomNonce
            );
        });

        it('should recover plaintext', () => {
            const result = recoverPlaintextUsingAesCtrEditOracle(ciphertext, editOracle); // TEST

            expect(result.includes('I\'m like Samson -- Samson to Delilah')).toEqual(true);
        });

    });
});
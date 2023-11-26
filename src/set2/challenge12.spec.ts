import {
    ConsistentKeyEncryptionOracle,
    consistentKeyEncryptionOracle, createLastByteDictionaryForBlockAndByte, decryptConsistentKeyEncryptionOracle,
    discoverBlockSize
} from './challenge12';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';

describe('Challenge 12', () => {
    let encryptionOracle: (plaintext: Buffer) => Buffer;

    beforeEach(() => {
       encryptionOracle = consistentKeyEncryptionOracle();
    });

    describe('Helper functions', () => {
       it('Should discover block size', () => {
           expect(discoverBlockSize(encryptionOracle)).toEqual(AES_128_BLOCK_LENGTH_BYTES); // TEST
       });

       describe('Last byte dictionary', () => {
           let knownPlaintext: Buffer;
           let dummyEncryptionOracle: ConsistentKeyEncryptionOracle;

           beforeEach(() => {
               knownPlaintext = Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                   16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]);
               dummyEncryptionOracle = function(plaintext: Buffer): Buffer {
                   return plaintext;
               };
           });

           it('Should create dictionary for the zeroth block', () => {
               const key = Buffer.from([0x41, 0x41, 0x41, 0x41, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0a, 0x7]);

               const result = createLastByteDictionaryForBlockAndByte(dummyEncryptionOracle, knownPlaintext, 0, 11); // TEST

               expect(Object.keys(result).length).toEqual(256);
               expect(result[key.toString('hex')]).toEqual(7);
           });

           it('Should create dictionary for the first block', () => {
               const key = Buffer.from([0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x11]);


               const result = createLastByteDictionaryForBlockAndByte(dummyEncryptionOracle, knownPlaintext, 1, 2); // TEST

               expect(Object.keys(result).length).toEqual(256);
               expect(result[key.toString('hex')]).toEqual(17);
           });
       });
    });

    describe('Byte-at-a-time ECB decryption', () => {
        xit('Should decrypt ciphertext', () => {
            const result = decryptConsistentKeyEncryptionOracle(encryptionOracle); // TEST

            console.log(result);
        });
    });
});
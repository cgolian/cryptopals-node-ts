import {
    aes128ComputeSubkeys, aes128DecryptBlock, aes128EcbDecrypt, aes128EcbEncrypt, aes128EncryptBlock,
    getAES128KeyForRound, invMixColumns, invShiftRows, invSubstituteBytes, mixColumns, shiftRows,
    splitTextIntoBlocks, substituteBytes,
    validateKeyLength,
    validateTextLength
} from './challenge7';
import {BitArray, Uint8BitArray} from './challenge1';
import * as fs from 'fs';

describe('Challenge 7', () => {
    describe('Validation functions', () => {
        it('should validate key 16 bytes long', () => {
            const key = Buffer.from('0000111122223333');

            expect(() => validateKeyLength(key)).not.toThrow(Error); // TEST
        });

        it('should throw error for key 10 bytes long', () => {
            const key = Buffer.from('0000111122');

            expect(() => validateKeyLength(key)).toThrow(Error); // TEST
        });

        it('should validate plaintext 32 bytes long', () => {
            const plaintext = Buffer.from('00000000111111112222222233333333');

            expect(() => validateTextLength(plaintext)).not.toThrow(Error); // TEST
        });

        it('should throw error for plaintext 31 bytes long', () => {
            const plaintext = Buffer.from('0000000011111111222222223333333');

            expect(() => validateTextLength(plaintext)).toThrow(Error); // TEST
        });
    });

    describe('Encryption - helper functions', () => {
        it('should split plaintext 32 bytes long into two blocks 16 bytes long', () => {
            const plaintext = Buffer.from('00000000111111112222222233333333');

            const result = splitTextIntoBlocks(plaintext, 16); // TEST

            expect(result.length).toEqual(2);
            expect(result[0]).toEqual(Buffer.from('0000000011111111'));
            expect(result[1]).toEqual(Buffer.from('2222222233333333'));
        });

        it('should compute subkeys array', () => {
            const key = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);

            const result = aes128ComputeSubkeys(key); // TEST

            expect(result.length).toEqual(44);
            // round 0 key
            expect((result[0] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0x00, 0x01, 0x02, 0x03));
            expect((result[1] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0x04, 0x05, 0x06, 0x07));
            expect((result[2] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0x08, 0x09, 0x0A, 0x0B));
            expect((result[3] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0x0C, 0x0D, 0x0E, 0x0F));
            // round 1 key
            expect((result[4] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0xD6, 0xAA, 0x74, 0xFD));
            expect((result[5] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0xD2, 0xAF, 0x72, 0xFA));
            expect((result[6] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0xDA, 0xA6, 0x78, 0xF1));
            expect((result[7] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0xD6, 0xAB, 0x76, 0xFE));
            // ...
            // round 9 key
            expect((result[36] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0x54, 0x99, 0x32, 0xD1));
            expect((result[37] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0xF0, 0x85, 0x57, 0x68));
            expect((result[38] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0x10, 0x93, 0xED, 0x9C));
            expect((result[39] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0xBE, 0x2C, 0x97, 0x4E));
            // round 10 key
            expect((result[40] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0x13, 0x11, 0x1D, 0x7F));
            expect((result[41] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0xE3, 0x94, 0x4A, 0x17));
            expect((result[42] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0xF3, 0x07, 0xA7, 0x8B));
            expect((result[43] as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0x4D, 0x2B, 0x30, 0xC5));
        });

        it('should get key for round', () => {
            const key = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);

            const words = aes128ComputeSubkeys(key);
            const result = getAES128KeyForRound(words, 9); // TEST

            expect((result as Uint8BitArray).bitArray).toEqual(Uint8Array.of(
                0x54, 0x99, 0x32, 0xD1, 0xF0, 0x85, 0x57, 0x68, 0x10, 0x93, 0xED, 0x9C, 0xBE, 0x2C, 0x97, 0x4E));
        });

        it('should substitute bytes', () => {
            const block = BitArray.fromHexString('3242F4AB8C5F368A393892A9EC3A093B');

            const result = substituteBytes(block); // TEST

            expect((result as Uint8BitArray).bitArray).toEqual(Uint8Array.of(
                0x23, 0x2C, 0xBF, 0x62, 0x64, 0xCF, 0x05, 0x7E, 0x12, 0x07, 0x4F, 0xD3, 0xCE, 0x80, 0x01, 0xE2));
        });

        it('should shift rows', () => {
            const block = BitArray.fromHexString('232CBF6264CF057E12074FD3CE8001E2');

            const result = shiftRows(block); // TEST

            expect((result as Uint8BitArray).bitArray).toEqual(Uint8Array.of(
                0x23, 0xCF, 0x4F, 0xE2, 0x64, 0x07, 0x01, 0x62, 0x12, 0x80, 0xBF, 0x7E, 0xCE, 0x2C, 0x05, 0xD3));
        });

        it('should mix columns', () => {
            const block = BitArray.fromHexString('23CF4FE2640701621280BF7ECE2C05D3');

            const result = mixColumns(block); // TEST

            expect((result as Uint8BitArray).bitArray).toEqual(Uint8Array.of(
                0xA1, 0x95, 0x4F, 0x3A, 0xA2, 0x0B, 0xC7, 0x6E, 0x7E, 0xAD, 0x75, 0xF5, 0x25, 0x4A, 0x86, 0xDD
            ));
        });

        it('should encrypt block', () => {
            const block = Buffer.from([0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34]);
            const key = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
            const expectedCiphertext = Buffer.from([0x89, 0xED, 0x5E, 0x6A, 0x05, 0xCA, 0x76, 0x33, 0x81, 0x35, 0x08, 0x5F, 0xE2, 0x1C, 0x40, 0xBD]);


            const subkeys = aes128ComputeSubkeys(key);
            const result = aes128EncryptBlock(block, subkeys); // TEST

            expect(result).toEqual(expectedCiphertext);
        });
    });

    describe('Decryption - helper functions', () => {
       it('should shift rows', () => {
           const block = BitArray.fromHexString('F533CC4755C0E74D4FB7F8EF99B145B2');

           const result = invShiftRows(block); // TEST

           expect((result as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0xF5, 0xB1, 0xF8, 0x4D, 0x55, 0x33, 0x45, 0xEF, 0x4F, 0xC0, 0xCC, 0xB2, 0x99, 0xB7, 0xE7, 0x47));
       });

        it('should mix columns', () => {
            const block = BitArray.fromHexString('2F9B8C755BB197424BC6395B169D6F3B');

            const result = invMixColumns(block); // TEST

            expect((result as Uint8BitArray).bitArray).toEqual(Uint8Array.of(0xF5, 0x33, 0xCC, 0x47, 0x55, 0xC0, 0xE7, 0x4D, 0x4F, 0xB7, 0xF8, 0xEF, 0x99, 0xB1, 0x45, 0xB2));
        });

        it('should substitute bytes', () => {
            const block = BitArray.fromHexString('F5B1F84D553345EF4FC0CCB299B7E747');

            const result = invSubstituteBytes(block); // TEST

            expect((result as Uint8BitArray).bitArray).toEqual(Uint8Array.of(
                0x77, 0x56, 0xE1, 0x65, 0xED, 0x66, 0x68, 0x61, 0x92, 0x1F, 0x27, 0x3E, 0xF9, 0x20, 0xB0, 0x16
            ));
        });

        it('should decrypt block', () => {
            const block = Buffer.from([0x89, 0xED, 0x5E, 0x6A, 0x05, 0xCA, 0x76, 0x33, 0x81, 0x35, 0x08, 0x5F, 0xE2, 0x1C, 0x40, 0xBD]);
            const key = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
            const expectedPlaintext = Buffer.from([0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34]);


            const subkeys = aes128ComputeSubkeys(key);
            const result = aes128DecryptBlock(block, subkeys); // TEST

            expect(result).toEqual(expectedPlaintext);
        });
    });

    describe('AES 128 ECB', () => {
        const expectedPlaintext = Buffer.from([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        ]);
        const expectedCiphertext = Buffer.from([
            0x0A, 0x94, 0x0B, 0xB5, 0x41, 0x6E, 0xF0, 0x45, 0xF1, 0xC3, 0x94, 0x58, 0xC6, 0x53, 0xEA, 0X5A,
            0x07, 0xFE, 0xEF, 0x74, 0xE1, 0xD5, 0x03, 0x6E, 0x90, 0x0E, 0xEE, 0x11, 0x8E, 0x94, 0x92, 0x93
        ]);

        const key = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);


        it('should encrypt plaintext longer than 16 bytes', () => {
            expect(aes128EcbEncrypt(expectedPlaintext, key)).toEqual(expectedCiphertext); // TEST
        });

        it('should decrypt ciphertext longer than 16 bytes', () => {
            expect(aes128EcbDecrypt(expectedCiphertext, key)).toEqual(expectedPlaintext); // TEST
        });
    });

    describe('Decrypt text in file', () => {
        it('should decrypt file content', () => {
            const fileContents = fs.readFileSync('./src/set1/7.txt', 'utf8');
            const ciphertext = Buffer.from(fileContents, 'base64');
            const key = Buffer.from('YELLOW SUBMARINE');

            const plaintext = aes128EcbDecrypt(ciphertext, key); // TEST

            expect(plaintext.includes('Play that funky music')).toBe(true);
        });
    });
});
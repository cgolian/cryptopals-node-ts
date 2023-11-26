import {hex2Base64, BitArray, Uint8BitArray} from './challenge1';

describe('Challenge 1', () => {

    describe('Bit array', function () {
        let bitArray: BitArray;

        beforeEach(() => {
            bitArray = new BitArray(24);
        });

        it('Should create an Uint8Array of size 3 to store 24 bits.', () => {
            expect((bitArray as Uint8BitArray).bitArray.length).toEqual(3); // TEST
        });

        it('Should throw an error trying to retrieve bit with index out of bounds #1.', () => {
            expect(() => bitArray.getBit(1111)).toThrow(Error); // TEST
        });

        it('Should throw an error trying to retrieve bit with index out of bounds #2.', () => {
            expect(() => bitArray.getBit(-1111)).toThrow(Error); // TEST
        });

        it('Should set bit', () => {
            bitArray.setBit(3);
            // 0001 0000 -> [16, 0, 0]
            expect((bitArray as Uint8BitArray).bitArray[0]).toEqual(16);

            bitArray.setBit(4);
            // 0001 1000 -> [24, 0, 0]
            expect((bitArray as Uint8BitArray).bitArray[0]).toEqual(24);

            bitArray.setBit(5);
            // 0001 1100 -> [28, 0, 0]
            expect((bitArray as Uint8BitArray).bitArray[0]).toEqual(28);

            bitArray.setBit(6);
            // 0001 1110 -> [30, 0, 0]
            expect((bitArray as Uint8BitArray).bitArray[0]).toEqual(30);

            bitArray.setBit(7);
            // 0001 1111 -> [31, 0, 0]
            expect((bitArray as Uint8BitArray).bitArray[0]).toEqual(31);

            bitArray.setBit(8);
            // 0001 1111 1000 0000 -> [31, 128, 0]
            expect((bitArray as Uint8BitArray).bitArray[0]).toEqual(31);
            expect((bitArray as Uint8BitArray).bitArray[1]).toEqual(128);

            bitArray.setBit(9);
            // 0001 1111 1100 0000 -> [31, 192, 0]
            expect((bitArray as Uint8BitArray).bitArray[0]).toEqual(31);
            expect((bitArray as Uint8BitArray).bitArray[1]).toEqual(192);
        });

        it('Should throw an error trying to set bit with index out of bounds #1.', () => {
            expect(() => bitArray.setBit(1111)).toThrow(Error); // TEST
        });

        it('Should throw an error trying to set bit with index out of bounds #2.', () => {
            expect(() => bitArray.setBit(-1111)).toThrow(Error); // TEST
        });

        it('Should clear bit', () => {
            bitArray.setBit(0);
            bitArray.setBit(1);
            bitArray.setBit(2);
            bitArray.setBit(3);
            bitArray.clearBit(2);

            // 1101 0000
            expect((bitArray as Uint8BitArray).bitArray[0]).toEqual(208); // TEST
        });

        it('Should get sextet stored in one uint8.', () => {
           // sextet should be 010 110 (22 dec)
           bitArray.setBit(10);
           bitArray.setBit(12);
           bitArray.setBit(13);

           const result = bitArray.getWord(9, 14); // TEST

           expect(result).toEqual(22);
        });

        it('Should get sextet stored in two uint8s.', () => {
            bitArray.setBit(6);
            bitArray.setBit(8);
            bitArray.setBit(10);

            const result = bitArray.getWord(6, 11); // TEST

            expect(result).toEqual(42);
        });

        it('should get octet stored in two uint8s', () => {
            bitArray.setBit(6);
            bitArray.setBit(9);
            bitArray.setBit(13);
            // what is stored is 10010001 (dec 145)

            const result = bitArray.getWord(6, 13); // TEST

            expect(result).toEqual(145);
        });

        it('Should throw an error getting word larger than 8 bits.', () => {
            expect(() => bitArray.getWord(0, 8)).toThrow(Error); // TEST
        });

        it('Should throw an error trying to retrieve invalid word.', () => {
            expect(() => bitArray.getWord(0, 8)).toThrow(Error); // TEST
        });

        it('Should convert BitArray to Buffer', () => {
            // should be 'hello'
            const buffer = Buffer.from([104, 101, 108, 108, 111]);
            const bitArray = BitArray.fromBuffer(buffer);

            const result = BitArray.toBuffer(bitArray); // TEST

            expect(result).toEqual(buffer);
        });

        it('Should convert BitArray to Buffer - number of bits not divisble by 8', () => {
            const bitArray = new BitArray(11);
            // 0000 1111 || 010|0 0000
            bitArray.setBit(4);
            bitArray.setBit(5);
            bitArray.setBit(6);
            bitArray.setBit(7);
            bitArray.setBit(9);

            const result = BitArray.toBuffer(bitArray); // TEST

            expect(result.length).toEqual(2);
            expect(result[0]).toEqual(15);
            expect(result[1]).toEqual(2);
        });

        it('Should convert Buffer to BitArray', () => {
            // should be 'hello'
            const buffer = Buffer.from([104, 101, 108, 108, 111]);

            const result = BitArray.fromBuffer(buffer); // TEST

            expect(result.getWord(0, 7)).toEqual(buffer[0]);
            expect(result.getWord(8, 15)).toEqual(buffer[1]);
            expect(result.getWord(16, 23)).toEqual(buffer[2]);
            expect(result.getWord(24, 31)).toEqual(buffer[3]);
            expect(result.getWord(32, 39)).toEqual(buffer[4]);
        });

        it('Should convert hex string to BitArray', () => {
            const result = BitArray.fromHexString('1234abcd'); // TEST

            expect(result.length).toEqual(32);
            // 0001 0010
            expect(result.getWord(0, 7)).toEqual(18);
            // 0011 0100
            expect(result.getWord(8, 15)).toEqual(52);
            // 1010 1011
            expect(result.getWord(16, 23)).toEqual(171);
            // 1010 1100
            expect(result.getWord(24, 31)).toEqual(205);
        });

        it('Should convert BitArray to hex string', () => {
            const expected = '1234abcd';

            const test = BitArray.fromHexString(expected);
            const result = BitArray.toHexString(test); // TEST

            expect(result).toEqual(expected);
        });

        it('Should fill with byte 0x01', () => {
            const byte = 0x01;

            const bitArray = new BitArray(32);
            bitArray.fillWithByte(byte); // TEST

            expect(bitArray.getWord(0, 7)).toEqual(byte);
            expect(bitArray.getWord(8, 15)).toEqual(byte);
            expect(bitArray.getWord(16, 23)).toEqual(byte);
            expect(bitArray.getWord(24, 31)).toEqual(byte);
        });
    });

    describe('Base64 conversion',  () => {
        it('Should not convert non-hexadecimal input.', () => {
            const msg = 'nonhex';

            expect(() => hex2Base64(msg)).toThrow(Error); // TEST
        });

        it('Should not convert non-hexadecimal input (input is of odd length).', () => {
            const msg = '747970656420617272617';

            expect(() => hex2Base64(msg)).toThrow(Error); // TEST
        });

        it('Should encode hex string in base64.', () => {
            const msg = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d';
            const expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t';

            const result = hex2Base64(msg); // TEST

            expect(result).toEqual(expected);
        });

        it('Should pad base64 encoded output.', () => {
            const msg = '7479706564206172726179';
            const expected = 'dHlwZWQgYXJyYXk=';

            const result = hex2Base64(msg); // TEST

            expect(result).toEqual(expected);
        });
    });
});

import {BitArray} from './challenge1';
import {decryptRepeatingKeyXOR, hamming, splitIntoBlocks, transposeBlocks} from './challenge6';
import * as fs from 'fs';

describe('Challenge 6', () => {
   describe('Hamming distance', () => {
        it('Should throw error for arrays of different length', () => {
            const m1 = Buffer.from('this');
            const m2 = Buffer.from('wokka wokka!!!');
            const arr1 = BitArray.fromBuffer(m1);
            const arr2 = BitArray.fromBuffer(m2);

            expect(() => hamming(arr1, arr2)).toThrow(Error); // TEST
        });

        it('Should be 37 for "this is a test" and "wokka wokka!!!"', () => {
            const m1 = Buffer.from('this is a test');
            const m2 = Buffer.from('wokka wokka!!!');
            const arr1 = BitArray.fromBuffer(m1);
            const arr2 = BitArray.fromBuffer(m2);

            const result = hamming(arr1, arr2); // TEST

            expect(result).toEqual(37);
        })
   });

   describe('Block manipulation', () => {
      it('Should split content into blocks', () => {
          const content = Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8]);

          const result = splitIntoBlocks(content, 3); // TEST

          expect(result.length).toEqual(3);
          expect(result[0]).toEqual(Buffer.from([0, 1, 2]));
          expect(result[1]).toEqual(Buffer.from([3, 4, 5]));
          expect(result[2]).toEqual(Buffer.from([6, 7, 8]));
      });

      it('Should transpose blocks', () => {
         const blocks = [
             Buffer.from([1, 2, 3, 4]),
             Buffer.from([5, 6, 7, 8]),
         ];

         const result = transposeBlocks(blocks, 4); // TEST

         expect(result.length).toEqual(4);
         expect(result[0]).toEqual(Buffer.from([1, 5]));
         expect(result[1]).toEqual(Buffer.from([2, 6]));
         expect(result[2]).toEqual(Buffer.from([3, 7]));
         expect(result[3]).toEqual(Buffer.from([4, 8]));
      });

       it('Should not transpose blocks', () => {
           const blocks = [
               Buffer.from([1, 2, 3]),
               Buffer.from([5, 6, 7]),
           ];

           expect(() => transposeBlocks(blocks, 4)).toThrow(Error); // TEST
       });
   });

   describe('XOR decryption', () => {
        let ciphertext: Buffer;

        beforeEach(() => {
           const fileContents = fs.readFileSync('./src/set1/6.txt', 'utf8');
           ciphertext = Buffer.from(fileContents, 'base64');
        });

        xit('Should decrypt ciphertext encrypted with repeating key XOR', () => {
            const result = decryptRepeatingKeyXOR(ciphertext); // TEST

            console.log(result.toString());
        });
   });
});
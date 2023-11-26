import {unpadBlockPKCS7} from './challenge15';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';

describe('Challenge 15', () => {
    describe('PKCS7 padding validation', () => {
       it('should strip valid padding', () => {
           const padded = Buffer.from('ICE ICE BABY\x04\x04\x04\x04');

           const result = unpadBlockPKCS7(padded, AES_128_BLOCK_LENGTH_BYTES); // TEST

           expect(result).toEqual(Buffer.from('ICE ICE BABY'));
       });

       it.each`
           input
           ${'ICE ICE BABY\x05\x05\x05\x05'} 
           ${'ICE ICE BABY\x01\x02\x03\x04'}
       `(`should throw error for input $input`, ({ input }) => {
           expect(() => unpadBlockPKCS7(Buffer.from(input), AES_128_BLOCK_LENGTH_BYTES)).toThrow(Error); // TEST
       });
    });
});
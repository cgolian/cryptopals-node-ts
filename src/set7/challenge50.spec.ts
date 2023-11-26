import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {computeAes128CbcMac} from './challenge49';
import {padPlaintextToMatchCbcMac} from './challenge50';

describe('Challenge 50', () => {
   describe('CBC MAC', () => {
       let plaintext: Buffer;
       let iv: Buffer;
       let key: Buffer;
       let expectedMAC: Buffer;

       beforeEach(() => {
           plaintext = Buffer.from('alert(\'MZA who was that?\');\n\x04\x04\x04\x04');
           iv = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES,0x0);
           key = Buffer.from('YELLOW SUBMARINE');
           expectedMAC = Buffer.from('296b8d7cb78a243dda4d0a61d33bbdd1', 'hex');
       });

       it('should compute the expected CBC-MAC', () => {
            const result = computeAes128CbcMac(plaintext, iv, key); // TEST

            expect(result).toEqual(expectedMAC);
       });

       it('should pad different string so that it has the same CBC MAC', () => {
            const differentPlaintext = Buffer.from('alert(\'Ayo, the Wu is back!\');  ');

            const paddedPlaintext = padPlaintextToMatchCbcMac(expectedMAC, differentPlaintext, iv, key); // TEST

            expect(computeAes128CbcMac(paddedPlaintext, iv, key)).toEqual(expectedMAC);
       });
   });
});
import {
    decryptWithMt19937,
    encryptKnownPlaintextWithRandomSeed,
    encryptWithMt19937, extractSeed,
    generateKeystreamFromRng, generatePasswordToken, isTokenMt19937EncryptedSeededWithTimestamp
} from './challenge24';
import {SeededRng} from "./challenge21";

describe('Challenge 24', () => {
   describe('generateKeystreamFromRng', () => {
       let rand: SeededRng;

       beforeEach(() => {
           rand = (): number => 0x1234;
       });

       it.each`
        bufferLength | expected
        ${3}         | ${Buffer.from([0x1, 0x2, 0x3])}
        ${5}         | ${Buffer.from([0x1, 0x2, 0x3, 0x4, 0x1])}
        ${6}         | ${Buffer.from([0x1, 0x2, 0x3, 0x4, 0x1, 0x2])}
        ${7}         | ${Buffer.from([0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3])}
        ${8}         | ${Buffer.from([0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4])}
        ${11}        | ${Buffer.from([0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3])}
       `(`should generate keystream of correct length for buffer`, ({bufferLength, expected}) => {
           const result = generateKeystreamFromRng(bufferLength, rand); // TEST

           expect(expected.length).toEqual(result.length);
           expect(expected).toEqual(result);
       });
   });

   describe('rng encryption', () => {
       let seed: number;

       beforeEach(() => {
           seed = 28;
       });

       it('should encrypt plaintext & decrypt the resulting ciphertext', () => {
          const plaintext = Buffer.from('I\'m sick and tired of 5-0 running up on the block');

          const ciphertext = encryptWithMt19937(plaintext, seed); // TEST
          const result = decryptWithMt19937(ciphertext, seed);

          expect(plaintext).toEqual(result);
       });
   });

   describe('encrypt known plaintext with random seed', () => {
       it('should encrypt known plaintext', () => {
           const plaintext = Buffer.from('aaaaaaaaaaaaaa');

           const result = encryptKnownPlaintextWithRandomSeed(plaintext); // TEST

           expect(result.ciphertext).toBeDefined();
       });

       xit('extract seed', () => {
           const plaintext = Buffer.from('aaaaaaaaaaaaaa');

           const encrypted = encryptKnownPlaintextWithRandomSeed(plaintext);
           const result = extractSeed(plaintext, encrypted.ciphertext); // TEST

           expect(result).toEqual(encrypted.seed);
       });
   });

   describe('generate password token', () => {
        xit('should detect token was encrypted with rng seeded with timestamp', () => {
            const encryptedToken = generatePasswordToken();

            expect(isTokenMt19937EncryptedSeededWithTimestamp(encryptedToken)).toEqual(true); // TEST
        });
   });
});
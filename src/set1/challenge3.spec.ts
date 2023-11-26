import {breakSingleByteXOR} from './challenge3';

describe('Challenge 3', () =>{
    describe('Single byte XOR key decryption', () => {
        it('Should decrypt string', () => {
            const ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736';
            const expected = 'Cooking MC\'s like a pound of bacon';

            const result = breakSingleByteXOR(ciphertext); // TEST

            const resultingPlaintext = result.plaintext.toString();
            expect(resultingPlaintext).toEqual(expected);
        });
    });
});
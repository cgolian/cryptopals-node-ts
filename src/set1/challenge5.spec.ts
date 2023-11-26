import {createXORKey, encryptWithXOR} from './challenge5';

describe('Challenge 5', () => {
    describe('Repeating key XOR', () => {
        it('Should create key out of phrase "ICE"', () => {
           const phrase = Buffer.from('ICE');
           const expected = Buffer.from('ICEICEICEI');

           const result = createXORKey(phrase, 10);

           expect(result.length).toEqual(10);
           expect(result).toEqual(expected);
        });

        it('Should encrypt input with key of the same length', () => {
            const expected = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' +
                'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f';
            const input = Buffer.from(
                'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal');
            const key = Buffer.from('ICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEIC');

            const result = encryptWithXOR(input, key); // TEST

            expect(result.toString('hex')).toEqual(expected);
        });

        it('Should not encrypt input shorter than key', () => {
            const input = Buffer.from(
                'a');
            const key = Buffer.from('ICE');

            expect(() => encryptWithXOR(input, key)).toThrow(Error); // TEST
        });

        it('Should encrypt input longer than key', () => {
            const expected = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' +
                'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f';
            const input = Buffer.from(
                'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal');
            const key = Buffer.from('ICE');

            const result = encryptWithXOR(input, key); // TEST

            expect(result.toString('hex')).toEqual(expected);
        });
    });
});
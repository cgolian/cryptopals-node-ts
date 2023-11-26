import {padBlockPKCS7, stripPKCS7} from './challenge9';

describe('Challenge 9', () => {
    describe('padBlockPKCS7', () => {
        it('should pad block', () => {
            const plaintext = Buffer.from('YELLOW SUBMARINE');

            const result = padBlockPKCS7(plaintext, 20); // TEST

            expect(result).toEqual(Buffer.from('YELLOW SUBMARINE\x04\x04\x04\x04'));
        });

        it('should pad plaintext with an extra padding block', () => {
            const plaintext = Buffer.from('aaaa');

            const result = padBlockPKCS7(plaintext, 4); // TEST

            expect(result).toEqual(Buffer.from('aaaa\x04\x04\x04\x04'));
        });

        it('should pad plaintext to two blocks', () => {
            const plaintext = Buffer.from('aaaabbbbccccddddee');

            const result = padBlockPKCS7(plaintext, 16); // TEST

            expect(result).toEqual(Buffer.from('aaaabbbbccccddddee\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'));
        });
    });

    describe('stripPKCS7', () => {
        it('should strip padding from padded text', () => {
            const padded = Buffer.from('aaaa\x04\x04\x04\x04');

            const result = stripPKCS7(padded, 4); // TEST

            expect(result).toEqual(Buffer.from('aaaa'));
        });
    });
});
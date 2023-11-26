import {computeMACwSHA1, verifyMACwSHA1} from './challenge28';

describe('Challenge 28', () => {
    describe('compute SHA1 MAC', () => {
        it('should compute expected hash', () => {
            const key = Buffer.from('shortkey');
            const message = Buffer.from('loooooooooooooooooooooooooooonginput');
            const expected = Buffer.from('fe81dfdedf1e380902ebda3f88edffcf58938eb3', 'hex');

            const result = computeMACwSHA1(message, key); // TEST

            expect(result).toEqual(expected);
        });
    });

    describe('verify SHA1 MAC', () => {
        it('should verify MAC', () => {
            const key = Buffer.from('shortkey');
            const message = Buffer.from('loooooooooooooooooooooooooooonginput');

            const mac = computeMACwSHA1(message, key);
            expect(verifyMACwSHA1(message, mac, key)).toEqual(true); // TEST
        });

        it('should not verify MAC that was tampered with', () => {
            const key = Buffer.from('shortkey');
            const message = Buffer.from('loooooooooooooooooooooooooooonginput');

            const mac = computeMACwSHA1(message, key);
            mac[5] = mac[5] + 1;
            expect(verifyMACwSHA1(message, mac, key)).toEqual(false); // TEST
        });
    });
});
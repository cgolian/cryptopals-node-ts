import * as crypto from 'crypto';
import {computeHMACwSHA1, insecureCompare} from "./challenge31";

describe('Challenge 31', () => {
    describe('insecure compare', () => {
        let buf1: Buffer;
        let buf2: Buffer;

        beforeEach(() => {
            buf1 = Buffer.from([0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6]);
            buf2 = Buffer.from([0x0, 0x1, 0x2, 0x3, 0x4, 0x7, 0x8]);
        });

        it('should return false when comparing different buffers', async () => {
            const result = await insecureCompare(buf1, buf2); // TEST

            expect(result).toEqual(false);
        });

        it('should take at least 200 ms to detect that fifth character in both buffers is different', async () => {
            const before = Date.now();
            await insecureCompare(buf1, buf2); // TEST
            const after = Date.now();

            expect((after - before) >= 200).toEqual(true);
        });
    });

    describe('HMAC with SHA1', () => {
        let msg: Buffer;
        let key: Buffer;
        let expected: Buffer;

        describe('key longer than block size', () => {
            beforeEach(() => {
                msg = Buffer.from('my secret msg');
                key = Buffer.from('looooooooooooooooooooooooooooooooooooooooooooooooooooooooooongkey');
                expected = crypto.createHmac('sha1', key).update(msg).digest();
            });

            it('should compute the same HMAC as nodes crypto library', () => {
                const result = computeHMACwSHA1(msg, key); // TEST

                expect(result).toEqual(expected);
            });
        });

        describe('key shorter than block size', () => {
            beforeEach(() => {
                msg = Buffer.from('my secret msg');
                key = Buffer.from('shortkey');
                expected = crypto.createHmac('sha1', key).update(msg).digest();
            });

            it('should compute the same HMAC as nodes crypto library', () => {
                const result = computeHMACwSHA1(msg, key); // TEST

                expect(result).toEqual(expected);
            });
        });
    });
});
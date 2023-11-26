import {ctrFlipBits, encryptData, isAdmin} from './challenge26';

describe('Challenge 16', () => {
    describe('CTR flip bits attack', () => {
        let encryptionFn: (userInput: string) => Buffer;
        let validationFn: (ciphertext: Buffer) => boolean;

        beforeEach(() => {
            encryptionFn = encryptData;
            validationFn = isAdmin;
        });

        it('should validate modified ciphertext', () => {
            const result = ctrFlipBits(encryptionFn, validationFn); // TEST

            expect(result).toBeDefined();
        });
    });
});
import {padBlockPKCS7} from '../set2/challenge9';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {
    aes128CbcEncryptWKeyAsIV,
    initRevealingPlaintextValidationOracle,
    recoverKeyUsingRevealingPlaintextValidationOracle, RevealingPlaintextValidationOracle
} from './challenge27';

describe('Challenge 27', () => {
    describe('validation oracle revealing plaintext', () => {
        let key: Buffer;
        let ciphertext: Buffer;
        let validationOracle: RevealingPlaintextValidationOracle;

        beforeEach(() => {
            key = Buffer.from('YELLOW SUBMARINE');
            validationOracle = initRevealingPlaintextValidationOracle(key);
            const msg = Buffer.from(
                "A licky boom boom down\nInformer, ya' no say daddy me Snow me I go blame\nA licky boom boom down");
            ciphertext = aes128CbcEncryptWKeyAsIV(padBlockPKCS7(msg, AES_128_BLOCK_LENGTH_BYTES), key);
        });

        it('should recover key using validation oracle', () => {
            const result = recoverKeyUsingRevealingPlaintextValidationOracle(ciphertext, validationOracle);

            expect(result).toEqual(key);
        });
    });
});
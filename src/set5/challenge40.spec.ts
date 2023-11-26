import {cubeRoot, decryptThreeTimesRSAEncryptedPlaintext} from './challenge40';
import { CryptoBigNumber } from './utils';
import {initRSA, RSAKey} from './challenge39';

describe('Challenge 40', () => {
    describe('cube root', () => {
        it('should compute cube root of 32768', () => {
            const input = new CryptoBigNumber(32768);
            const expected = new CryptoBigNumber(32);

            const result = cubeRoot(input, 1000); // TEST

            expect(expected).toEqual(result);
        });
    });

    xdescribe('E=3 RSA Broadcast attack', () => {
        let plaintext: Buffer;
        let ciphertexts: Buffer[];
        let publicKeys: RSAKey[];

        beforeEach(() => {
            plaintext = Buffer.from('Message encrypted three times');
            ciphertexts = [];
            publicKeys = [];

            const rsaFunctions = initRSA();
            for (let i = 0; i < 3; i++) {
                const keyPair = rsaFunctions.generateKeyPair(3, 300);
                const ciphertext = rsaFunctions.encryptMessage(plaintext, keyPair.publicKey);
                ciphertexts.push(ciphertext);
                publicKeys.push(keyPair.publicKey);
            }
        });

        it('should decrypt same plaintext encrypted three times with different moduli but e = 3', () => {
            const result = decryptThreeTimesRSAEncryptedPlaintext(ciphertexts, publicKeys); // TEST

            expect(plaintext).toEqual(result);
        });
    });
});
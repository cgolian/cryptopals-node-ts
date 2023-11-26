import { CryptoBigNumber } from "./utils";
import {generateRandomPrime, initRSA, isProbablePrime, modinv, RSAFunctions, RSAKeyPair} from "./challenge39";

describe('Challenge 39', () => {
    describe('modular inverse', () => {
        it('should compute modular inverse', () => {
            const a = new CryptoBigNumber(17);
            const n = new CryptoBigNumber(23);
            const expected = new CryptoBigNumber(19);

            const result = modinv(a, n); // TEST

            expect(result).toEqual(expected);
        });

        it('should throw for non-invertible number', () => {
            const a = new CryptoBigNumber(17);
            const n = new CryptoBigNumber(34);

            expect(() => modinv(a, n)).toThrow(Error); // TEST
        });
    });

    describe('prime generation', () => {
        it('should determine that 91 is composite', () => {
            const result = isProbablePrime(new CryptoBigNumber(91)); // TEST

            expect(result).toEqual(false);
        });

        it('should determine that 61603 is prime', () => {
            const result = isProbablePrime(new CryptoBigNumber(61603)); // TEST

            expect(result).toEqual(true);
        });

        it('should generate random prime number', () => {
            const result = generateRandomPrime(100); // TEST

            expect(isProbablePrime(result)).toEqual(true);
        });
    });

    describe('RSA', () => {
        let rsaFunctions: RSAFunctions;
        let keyPair: RSAKeyPair;

        beforeEach(() => {
            rsaFunctions = initRSA();
            keyPair = rsaFunctions.generateKeyPair(3, 256);
        });

        it('should encrypt & decrypt string using RSA', () => {
            const plaintext = Buffer.from('secret message');

            const ciphertext = rsaFunctions.encryptMessage(plaintext, keyPair.publicKey); // TEST
            const result = rsaFunctions.decryptMessage(ciphertext, keyPair.privateKey); // TEST

            expect(result).toEqual(plaintext);
        });
    });
});
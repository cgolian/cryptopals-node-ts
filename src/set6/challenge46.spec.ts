import {initRSA, RSAFunctions, RSAKeyPair} from "../set5/challenge39";
import {
    binaryLogarithm,
    decryptRSACiphertextWithParityOracle,
    initRSAParityOracle,
    RSAParityOracle
} from "./challenge46";
import { CryptoBigNumber } from "../set5/utils";

describe('Challenge 46', () => {
    let rsaParityOracle: RSAParityOracle;
    let rsaKeyPair: RSAKeyPair;
    let rsaFunctions: RSAFunctions;

    beforeEach(() => {
        rsaFunctions = initRSA();
        const privateKey = {
            exponent: new CryptoBigNumber('00ab121aac6614b13f664f89033154' +
                '20a4404035050faa91acc089dedce1c30cfc5d220a68dfe1e96048da7cfd' +
                '0271aa7ccc6f8031e3f96ef0a6a3c62f93e395297817043823c7fa452d8e' +
                '62d050e90aeb23a98c03d471a4172b9f1756feeb2297fb4cf9473199c0a9' +
                'a60c2e867bc01930d1d131f170670a539096117d2a3e1b79', 16),
            modulus: new CryptoBigNumber('00ad97a410fbd8a9309b1f302eb7e4' +
                '73a1ef7500ebb03b4da4c1408618e7229024e3263a8e7172389259e6be03' +
                '5df0a5e6c32b52911d3ef7d4bcde09a93dc7a9c65d8d337c873e1a48d12e' +
                '7fac59708d41950c258a05742f17a96a30b0a6558f76fd3edf86bc20720c' +
                '70ce867b013d0c77651b7cddb7f8eb6ecb67495951f10ba7', 16)
        };
        const publicKey = {
            exponent: new CryptoBigNumber(65537, 10),
            modulus: new CryptoBigNumber('00ad97a410fbd8a9309b1f302eb7e4' +
                '73a1ef7500ebb03b4da4c1408618e7229024e3263a8e7172389259e6be03' +
                '5df0a5e6c32b52911d3ef7d4bcde09a93dc7a9c65d8d337c873e1a48d12e' +
                '7fac59708d41950c258a05742f17a96a30b0a6558f76fd3edf86bc20720c' +
                '70ce867b013d0c77651b7cddb7f8eb6ecb67495951f10ba7', 16)
        };
        rsaKeyPair = {
            publicKey,
            privateKey
        };
        rsaParityOracle = initRSAParityOracle(rsaKeyPair);
    });

    describe('RSA parity oracle', () => {
        it('should return false for odd plaintext', () => {
            const plaintext = Buffer.from('\x02\x00\x00\x00\x00\x01');

            const ciphertext = rsaFunctions.encryptMessage(plaintext, rsaKeyPair.publicKey);
            const result = rsaParityOracle.isPlaintextEven(ciphertext); // TEST

            expect(result).toEqual(false);
        });

        it('should return true for even plaintext', () => {
            const plaintext = Buffer.from('\x03\x00\x00\x00\x00\x08');

            const ciphertext = rsaFunctions.encryptMessage(plaintext, rsaKeyPair.publicKey);
            const result = rsaParityOracle.isPlaintextEven(ciphertext); // TEST

            expect(result).toEqual(true);
        });
    });

    describe('binary logarithm', () => {
        it('should compute binary logarithm of 8192', () => {
            const result = binaryLogarithm(new CryptoBigNumber(8192)); // TEST

            expect(result).toEqual(13);
        });
    });

    xdescribe('decrypt RSA parity oracle', () => {
        it('should decrypt ciphertext', () => {
            const plaintext = Buffer.from(
                'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==', 'base64');
            const ciphertext = rsaFunctions.encryptMessage(plaintext, rsaKeyPair.publicKey);

            const result = decryptRSACiphertextWithParityOracle(ciphertext, rsaKeyPair.publicKey, rsaParityOracle); // TEST

            expect(result).toEqual(plaintext);
        });
    });
});
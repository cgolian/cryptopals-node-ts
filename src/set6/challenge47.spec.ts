import {
    decryptPKCSPaddingOracleSimple,
    initPKCS1v15Padder,
    initPKCSPaddingOracle,
    PKCS1v15Padder,
    PKCSPaddingOracle
} from './challenge47';
import {initRSA, RSAFunctions, RSAKeyPair} from '../set5/challenge39';
import {CryptoBigNumber} from "../set5/utils";

describe('Challenge 47', () => {
    describe('PKCS padding', () => {
        let padder: PKCS1v15Padder;

        beforeEach(() => {
            padder = initPKCS1v15Padder();
        });

        it('should pad in PKCS1v1.5 format', () => {
            const msg = Buffer.from(`hi mom`);

            const padded = padder.pad(msg, 32); // TEST

            expect(padded.length).toEqual(32);
            expect(padded[0]).toEqual(0x00);
            expect(padded[1]).toEqual(0x02);
            expect(padded.indexOf(0x00, 2)).toEqual(padded.length - msg.length - 1);
        });

        it('should throw - input too long', () => {
            const msg = Buffer.from(`hi mom`);

            expect(() => padder.pad(msg, 8)).toThrow(Error); // TEST
        });

        it('should strip PKCS1v1.5 padding', () => {
            const msg = Buffer.from(`hi mom`);

            const padded = padder.pad(msg, 32);
            const stripped = padder.strip(padded); // TEST

            expect(msg).toEqual(stripped);
        });

        it('should throw - input not in PKCS1v1.5 format', () => {
            const msg = Buffer.from(`hi mom`);

            const padded = padder.pad(msg, 32);
            padded[1] = 0xFF;
            expect(() => padder.strip(padded)).toThrow(Error); // TEST
        });
    });

    describe('PKCS padding oracle', () => {
        let rsaFunctions: RSAFunctions;
        let rsaKeyPair: RSAKeyPair;
        let paddingOracle: PKCSPaddingOracle;
        let padder: PKCS1v15Padder;

        beforeEach(() => {
            rsaFunctions = initRSA();
            rsaKeyPair = rsaFunctions.generateKeyPair(7, 256);
            paddingOracle = initPKCSPaddingOracle(rsaKeyPair);
            padder = initPKCS1v15Padder();
        });

        it('should return true for correctly padded plaintext', () => {
            const msg = Buffer.from(`kick it, CC`);
            const padded = padder.pad(msg, 32);
            const encrypted = rsaFunctions.encryptMessage(padded, rsaKeyPair.publicKey);

            const result = paddingOracle.isPlaintextPadded(encrypted); // TEST

            expect(result).toEqual(true);
        });

        it('should return false for plaintext which is not padded', () => {
            const msg = Buffer.from(`kick it, CC`);
            const padded = padder.pad(msg, 32);
            padded[1] = 0x77;
            const encrypted = rsaFunctions.encryptMessage(padded, rsaKeyPair.publicKey);

            const result = paddingOracle.isPlaintextPadded(encrypted); // TEST

            expect(result).toEqual(false);
        });
    });

    xdescribe('PKCS padding oracle attack (easy)', () => {
        let rsa: RSAFunctions;
        let rsaKeyPair: RSAKeyPair;
        let msg: Buffer;
        let padder: PKCS1v15Padder;
        let encrypted: Buffer;
        let oracle: PKCSPaddingOracle;

        beforeEach(() => {
            rsa = initRSA();
            rsaKeyPair = {
                privateKey: {
                    exponent: new CryptoBigNumber('28538780907521151365105004358183044959091793723330827427102825592805338732155', 10),
                    modulus: new CryptoBigNumber('42808171361281727047657506537274567439057747209816724612107287485075510888491', 10)
                },
                publicKey: {
                    exponent: new CryptoBigNumber(3, 10),
                    modulus: new CryptoBigNumber('42808171361281727047657506537274567439057747209816724612107287485075510888491', 10)
                }
            };
            msg = Buffer.from('kick it, CC');
            padder = initPKCS1v15Padder();
            const padded = padder.pad(msg, 32);
            encrypted = rsa.encryptMessage(padded, rsaKeyPair.publicKey);
            oracle = initPKCSPaddingOracle(rsaKeyPair);
        });

        it('should recover plaintext', () => {
            const result = decryptPKCSPaddingOracleSimple(encrypted, rsaKeyPair.publicKey, oracle); // TEST

            expect(result.includes(msg)).toEqual(true);
        });
    });
});
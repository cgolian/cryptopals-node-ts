import {initRSA, RSAFunctions, RSAKeyPair} from '../set5/challenge39';
import {
    initPKCS1v15Padder,
    initPKCSPaddingOracle,
    PKCS1v15Padder,
    PKCSPaddingOracle
} from './challenge47';
import {CryptoBigNumber} from '../set5/utils';
import {decryptPKCSPaddingOracleComplete} from "./challenge48";

describe('Challenge 48', () => {
    xdescribe('PKCS padding oracle (complete)', () => {
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
                    exponent: new CryptoBigNumber('7a2c4747a0aff23b507757d7cb6742a92bc7a18967dda33d3848af0d58a08dde0' +
                        'b8efea367cd95cdff42f74cacc04f97f9a7c375d549e654ede9958f14a89aa6643e3b2ab927cd28cfb2ac9a9f03b8b' +
                        '1fbebcdfba880c875dea7150bd7fdfeab', 16),
                    modulus: new CryptoBigNumber('11113812591433862124286107229992142772824445810698109052370333763657' +
                        '38082945975692945913350490700006189020312804696322336010866356548672' +
                        '92189389474709925487852753803836518780831418512779194799621600479681' +
                        '4206940626959182604304709423', 10)
                },
                publicKey: {
                    exponent: new CryptoBigNumber(3, 10),
                    modulus: new CryptoBigNumber('11113812591433862124286107229992142772824445810698109052370333763657' +
                        '38082945975692945913350490700006189020312804696322336010866356548672' +
                        '92189389474709925487852753803836518780831418512779194799621600479681' +
                        '4206940626959182604304709423', 10)
                }
            };
            msg = Buffer.from('kick it, CC');
            padder = initPKCS1v15Padder();
            const padded = padder.pad(msg, 96);
            encrypted = rsa.encryptMessage(padded, rsaKeyPair.publicKey);
            oracle = initPKCSPaddingOracle(rsaKeyPair);
        });

        it('should recover plaintext', () => {
            const result = decryptPKCSPaddingOracleComplete(encrypted, rsaKeyPair.publicKey, oracle); // TEST

            expect(result.includes(msg)).toEqual(true);
        });
    });
});
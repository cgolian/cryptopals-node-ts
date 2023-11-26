import {CryptoBigNumber} from '../set5/utils';
import {DSAParams, DSASignatureFunctions, initDSASignature} from './challenge43';
import {generateValidDSASignature} from "./challenge45";

describe('Challenge 45', () => {
    let dsaSignatureFunctions: DSASignatureFunctions;
    let dsaParams: DSAParams;

    describe('g = 0', () => {
        beforeEach(() => {
            dsaParams = {
                p: new CryptoBigNumber('0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578' +
                    'b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fd' +
                    'a812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1', 16),
                q: new CryptoBigNumber('0xf4f47f05794b256174bba6e9b396a7707e563c5b', 16),
                g: new CryptoBigNumber(0)
            };
            dsaSignatureFunctions = initDSASignature(dsaParams);
        });

        it('should verify signed message', () => {
            const zero = new CryptoBigNumber(0);
            const msg = Buffer.from('msg');
            // does not matter which values we are using here
            const privateKey = new CryptoBigNumber(1111_2222);
            const publicKey = new CryptoBigNumber(2222_8888);

            const signature = dsaSignatureFunctions.sign(msg, privateKey);

            const result = dsaSignatureFunctions.verify(msg, signature, publicKey); // TEST

            expect(result).toEqual(true);
            expect(signature.r).toEqual(zero);
        });
    });

    describe('g = p + 1', () => {
        beforeEach(() => {
            dsaParams = {
                p: new CryptoBigNumber('0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578' +
                    'b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fd' +
                    'a812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1', 16),
                q: new CryptoBigNumber('0xf4f47f05794b256174bba6e9b396a7707e563c5b', 16),
                g: dsaParams.p.plus(1)
            };
            dsaSignatureFunctions = initDSASignature(dsaParams);
        });

        it('Should generate valid signature for "Hello, world"', () => {
            const msg = Buffer.from('Hello, world');
            const publicKey = new CryptoBigNumber('11111117');

            const signature = generateValidDSASignature(msg, publicKey, dsaParams); // TEST
            const result = dsaSignatureFunctions.verify(msg, signature, publicKey);

            expect(result).toEqual(true);
        });

        it('Should generate valid signature for "Goodbye, world"', () => {
            const msg = Buffer.from('Goodbye, world');
            const publicKey = new CryptoBigNumber('11111117');

            const signature = generateValidDSASignature(msg, publicKey, dsaParams); // TEST
            const result = dsaSignatureFunctions.verify(msg, signature, publicKey);

            expect(result).toEqual(true);
        });
    });
});
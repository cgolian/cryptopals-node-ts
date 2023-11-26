import {
    DSAParams,
    DSASignature,
    DSASignatureFunctions,
    initDSASignature,
    recoverDSAPrivateKeyFromNonce
} from "./challenge43";
import {CryptoBigNumber, sha1} from "../set5/utils";
import { BigNumber } from "bignumber.js";

describe('Challenge 43', () => {
    let dsaParams: DSAParams;
    let msg: Buffer;
    let signature: DSASignature;
    let publicKey: BigNumber;

    beforeEach(() => {
        dsaParams = {
            p: new CryptoBigNumber('0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578' +
                'b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fd' +
                'a812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1', 16),
            q: new CryptoBigNumber('0xf4f47f05794b256174bba6e9b396a7707e563c5b', 16),
            g: new CryptoBigNumber('0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db6' +
                '20c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556' +
                'fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291', 16)
        };
        msg = Buffer.from('For those that envy a MC it can be hazardous to your health\n' +
            'So be friendly, a matter of life and death, just like a etch-a-sketch\n');
        signature = {
            r: new CryptoBigNumber('548099063082341131477253921760299949438196259240', 10),
            s: new CryptoBigNumber('857042759984254168557880549501802188789837994940', 10)
        };
        publicKey = new CryptoBigNumber('0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4' +
            'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004' +
            'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed' +
            '1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b' +
            'bb283e6633451e535c45513b2d33c99ea17'
        );
    });

    describe('DSA', () => {
        let dsaSignatureFunctions: DSASignatureFunctions;

        beforeEach(() => {
            dsaSignatureFunctions = initDSASignature(dsaParams);
        });

        it('should verify message', () => {
            const result = dsaSignatureFunctions.verify(msg, signature, publicKey); // TEST

            expect(result).toEqual(true);
        });

        it('should not verify message', () => {
            const tamperedSignature = {...signature};
            tamperedSignature.r = tamperedSignature.r.minus(10);

            const result = dsaSignatureFunctions.verify(msg, tamperedSignature, publicKey); // TEST

            expect(result).toEqual(false);
        });
    });

    xdescribe('DSA key recovery from nonce', () => {
        it('should recover private key using a known private ephemeral key', () => {
            const expectedDigest = Buffer.from("0954edd5e0afe5542a4adf012611a91912a3ec16", "hex");

            let kFound = false;
            let keyDigest;
            for (let k = 0; k <= 65536; k++) {
                const bigK = new CryptoBigNumber(k, 10);
                const result = (dsaParams.g.exponentiatedBy(bigK, dsaParams.p)).mod(dsaParams.q);
                if (result.eq(signature.r)) {
                    const possiblePrivateKey = recoverDSAPrivateKeyFromNonce(msg, signature, bigK, dsaParams); // TEST
                    keyDigest = sha1(possiblePrivateKey.toString(16));
                    kFound = true;
                    break;
                }
            }

            expect(kFound).toEqual(true);
            expect(expectedDigest).toEqual(keyDigest);
        });
    });
});
import { BigNumber } from 'bignumber.js';

import {modinv, RSAKey} from './challenge39';
import {CryptoBigNumber} from './utils';

export function cubeRoot(number: BigNumber, iterations: number): BigNumber {
    const two = new CryptoBigNumber(2);
    const three = new CryptoBigNumber(3);
    let xN = number.div(three);
    let xNplus1 = new CryptoBigNumber(-1);
    for (let i = 0; i < iterations; i++) {
        xNplus1 = ((number.div(xN.pow(two))).plus(two.times(xN)).div(three));
        xN = xNplus1;
    }
    return xNplus1;
}

export function decryptThreeTimesRSAEncryptedPlaintext(ciphertexts: ReadonlyArray<Buffer>, publicKeys: ReadonlyArray<RSAKey>): Buffer {
    if (ciphertexts.length != 3 || publicKeys.length != 3) {
        throw Error(`Cannot be decrypted.`);
    }
    const n0 = publicKeys[0].modulus;
    const n1 = publicKeys[1].modulus;
    const n2 = publicKeys[2].modulus;
    // compute products of the moduli
    const n0TimesN1 = n0.times(n1);
    const n0TimesN2 = n0.times(n2);
    const n1TimesN2 = n1.times(n2);
    const N = n0TimesN1.times(n2);
    // c0 = ct0 * (n1*n2) * invmod((n1*n2), n0)
    const c0 = new CryptoBigNumber(ciphertexts[0].toString('hex'), 16)
        .times(n1TimesN2.times(modinv(n1TimesN2, n0)));
    // c1 = ct1 * (n0*n2) * invmod((n0*n2), n1)
    const c1 = new CryptoBigNumber(ciphertexts[1].toString('hex'), 16)
        .times(n0TimesN2.times(modinv(n0TimesN2, n1)));
    // c2 = ct2 * (n0*n1) * invmod((n0*n1), n2)
    const c2 = new CryptoBigNumber(ciphertexts[2].toString('hex'), 16)
        .times(n0TimesN1.times(modinv(n0TimesN1, n2)));
    // CRT = (c0 + c1 + c2) mod n0*n1*n2
    const cubed = c0.plus(c1).plus(c2).mod(N);
    const plaintext = cubeRoot(cubed, 10_000);
    return Buffer.from(plaintext.toString(16), 'hex');
}
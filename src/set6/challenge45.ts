import { DSASignature} from './challenge43';
import { BigNumber } from 'bignumber.js';
import { modinv } from '../set5/challenge39';
import { CryptoBigNumber } from '../set5/utils';

/*
Generate valid signature:

"fake" signing:
r = ((y ^ z) mod p) mod q
s =  r * z^-1 mod q

verifying:
w = (r * z^-1)^-1 mod q
w = r^-1 * z mod q

u1 = H(z) * r^-1 * z mod q

u2 = r * r^-1 * z mod q
u2 = z mod q

v = ((g^u1 * y^u2) mod p) mod q
v = ((1 * y^u2) mod p) mod q
v = ((y ^ z) mod p) mod q)

*/
export function generateValidDSASignature(
    msg: Buffer,
    publicKey: BigNumber,
    dsaParams: { p: BigNumber; q: BigNumber; g: BigNumber }
): DSASignature {
    if (!dsaParams.g.eq(dsaParams.p.plus(1))) {
        throw Error(`Valid signature cannot be generated`);
    }
    const msgNum = new CryptoBigNumber(msg.toString('hex'), 16);
    const invMsgNum = modinv(msgNum, dsaParams.q);
    const r = publicKey.exponentiatedBy(msgNum, dsaParams.p).mod(dsaParams.q);
    const s = r.times(invMsgNum).mod(dsaParams.q);
    return {
        r,
        s
    };
}
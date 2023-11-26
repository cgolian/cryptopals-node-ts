import { BigNumber } from 'bignumber.js';
import {DSAParams, recoverDSAPrivateKeyFromNonce} from './challenge43';
import {modinv} from "../set5/challenge39";
import { CryptoBigNumber } from '../set5/utils';

export type DSASignedMessage = {
    msg: Buffer;
    r: BigNumber;
    s: BigNumber;
    m: Buffer;
}

export type DSASignedMessagePair = {
    signedMsg1: DSASignedMessage;
    signedMsg2: DSASignedMessage;
};

/*
*       (m1 - m2)
* k_e = --------- mod q
*       (s1 - s2)
*
*       SHA1(msg1) - SHA1(msg2)
* k_e = ----------------------------------------------------------------------------------------------------- mod q
*       ((SHA1(msg1) + privateKey * r) * invmod(k_e, q) - (SHA1(msg2) + privateKey * r) * invmod(k_e, q))
*
* k_e = SHA1(msg1) - SHA1(msg2)
*       -----------------------                     mod q
*       (SHA1(msg1) - SHA1(msg2)) * invmod(k_e, q)
*
* k_e =       1
*       --------------- mod q
*       invmod(k_e, q)
*
* */
export function recoverDSAPrivateKeyFromRepeatedNonce(
    msgPair: DSASignedMessagePair,
    dsaParams: DSAParams
): BigNumber {
    const msg1DigestNum = new CryptoBigNumber(msgPair.signedMsg1.m.toString('hex'), 16);
    const msg2DigestNum = new CryptoBigNumber(msgPair.signedMsg2.m.toString('hex'), 16);
    const numerator = msg1DigestNum.minus(msg2DigestNum).mod(dsaParams.q);
    const denominator = msgPair.signedMsg1.s.minus(msgPair.signedMsg2.s).mod(dsaParams.q);
    const invDenominator = modinv(denominator, dsaParams.q);
    const ephemeralPrivateKey = numerator.times(invDenominator).mod(dsaParams.q);
    return recoverDSAPrivateKeyFromNonce(
        msgPair.signedMsg1.msg,
        {
            r: msgPair.signedMsg1.r,
            s: msgPair.signedMsg1.s
        },
        ephemeralPrivateKey,
        dsaParams
    );
}
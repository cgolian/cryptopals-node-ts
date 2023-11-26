import { BigNumber } from "bignumber.js";
import {modinv} from "../set5/challenge39";
import {CryptoBigNumber} from "../set5/utils";
import * as crypto from "crypto";

export type DSAParams = {
    p: BigNumber;
    q: BigNumber;
    g: BigNumber;
};

export type DSASignature = {
    r: BigNumber;
    s: BigNumber;
}

export interface DSASignatureFunctions {
    /**
     * Sign message with DSA
     *
     * k_e = randInt() mod q
     * r = (g ^ k_e mod p) mod q
     * s = (SHA1(x) + privateKey * r) * invmod(k_e, q) mod q
     *
     * @param message message which is going to be signed
     * @param privateKey DSA private key
     */
    sign(message: Buffer, privateKey: BigNumber): DSASignature;

    /**
     * Verify message signed with DSA
     *
     * w = invmod(s, q);
     * u1 = w * SHA1(message) mod q
     * u2 = w * r mod q
     * v = ((generator ^ u1) * (publicKey ^ u2) mod p) mod q
     *
     * @param message message which is going to be verified
     * @param signature DSA signature
     * @param publicKey DSA public key
     */
    verify(message: Buffer, signature: DSASignature, publicKey: BigNumber): boolean;
}

// return BigNumber representing the message digest
function sha1Numeric(message: Buffer): BigNumber {
    const digest = crypto.createHash('sha1').update(message).digest();
    return new CryptoBigNumber(digest.toString('hex'), 16);
}

export function initDSASignature(params: DSAParams): DSASignatureFunctions {
    function sign(message: Buffer, privateKey: BigNumber): DSASignature {
        const ephemeralPrivateKey = CryptoBigNumber.random().times(params.q.minus(1)).integerValue(BigNumber.ROUND_CEIL);
        const invEphemeralPrivateKey = modinv(ephemeralPrivateKey, params.q);
        const messageDigestNum = sha1Numeric(message);
        const r = (params.g.exponentiatedBy(ephemeralPrivateKey, params.p)).mod(params.q);
        const s = invEphemeralPrivateKey.times(messageDigestNum.plus(privateKey.times(r))).mod(params.q);
        return {
            r,
            s
        };
    }

    function verify(message: Buffer, signature: DSASignature, pubKey: BigNumber): boolean {
        const messageDigestNum = sha1Numeric(message);
        const w = modinv(signature.s, params.q);
        const u1 = w.times(messageDigestNum).mod(params.q);
        const u2 = w.times(signature.r).mod(params.q);
        const v = ((params.g.exponentiatedBy(u1, params.p)).times(pubKey.exponentiatedBy(u2, params.p)).mod(params.p))
            .mod(params.q);
        return signature.r.isEqualTo(v);
    }

    return {
        sign,
        verify
    };
}

/**
 * Recover private key using known ephemeral private key.
 *
 * s = (SHA1(x) + privateKey * r) * invmod(k_e, q) mod q
 * s = ((SHA1(msg) + privateKey * r) / k_e) mod q
 * s * k_e = (SHA1(msg) + privateKey * r) mod q
 * s * k_e - SHA1(msg) = privateKey * r mod q
 * (s * k_e - SHA1(msg)) * invmod(r,q) = privateKey mod q
 *
 * @param message
 * @param signature
 * @param ephemeralPrivateKey
 * @param dsaParams
 */
export function recoverDSAPrivateKeyFromNonce(
    message: Buffer,
    signature: DSASignature,
    ephemeralPrivateKey: BigNumber,
    dsaParams: DSAParams
): BigNumber {
    const invR = modinv(signature.r, dsaParams.q);
    const messageDigestNum = sha1Numeric(message);
    const sTimesK = signature.s.times(ephemeralPrivateKey);
    return (((sTimesK).minus(messageDigestNum)).times(invR)).mod(dsaParams.q);
}
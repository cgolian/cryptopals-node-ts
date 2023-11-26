import {RSAKey} from '../set5/challenge39';
import {CryptoBigNumber} from '../set5/utils';
import {bbSearchForS, bbSearchOneInterval, bbUpdateIntervals, PKCSPaddingOracle} from './challenge47';

export function decryptPKCSPaddingOracleComplete(
    pkcsCompliantCiphertext: Buffer,
    publicKeyUsed: RSAKey,
    oracle: PKCSPaddingOracle,
): Buffer {
    const two = new CryptoBigNumber(2), three = new CryptoBigNumber(3);
    const B = two.exponentiatedBy(752), twoB = two.times(B), threeB = three.times(B);
    let plaintextDecrypted = false;
    let intervals = [[twoB, threeB.minus(1)]];

    // we skip step 1 since we assume that original plaintext is PKCS padded
    const lowerBound = publicKeyUsed.modulus.dividedToIntegerBy(three.times(B));
    let s = bbSearchForS(lowerBound, pkcsCompliantCiphertext, publicKeyUsed, oracle);
    intervals = bbUpdateIntervals(intervals, s, B, publicKeyUsed);
    while (!plaintextDecrypted) {
        if (intervals.length === 1) {
            if (intervals[0][0].eq(intervals[0][1])) {
                plaintextDecrypted = true;
            } else {
                s = bbSearchOneInterval(intervals[0][0], intervals[0][1], publicKeyUsed, s, B, pkcsCompliantCiphertext, oracle);
                intervals = bbUpdateIntervals(intervals, s, B, publicKeyUsed);
            }
        } else {
            s = bbSearchForS(s, pkcsCompliantCiphertext, publicKeyUsed, oracle);
            intervals = bbUpdateIntervals(intervals, s, B, publicKeyUsed);
        }
    }
    let plaintextStr = intervals[0][0].toString(16);
    if (plaintextStr.length % 2 != 0) plaintextStr = '0'.concat(plaintextStr);
    return Buffer.from(plaintextStr, 'hex');
}
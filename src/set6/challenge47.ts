import {initRSA, RSAKey, RSAKeyPair} from '../set5/challenge39';
import { CryptoBigNumber } from '../set5/utils';
import { BigNumber } from 'bignumber.js';

const two = new CryptoBigNumber(2), three = new CryptoBigNumber(3);

export interface PKCS1v15Padder {
    /**
     * Pad input to desired length
     * @param input
     * @param length
     */
    pad(input: Buffer, length: number): Buffer;

    /**
     * Strip padding
     * @param input
     */
    strip(input: Buffer): Buffer;
}

export interface PKCSPaddingOracle {
    /**
     * Return true if RSA encrypted plaintext is padded in PKCS1v1.5 format
     * @param ciphertext
     */
    isPlaintextPadded(ciphertext: Buffer): boolean;
}

export function initPKCSPaddingOracle(rsaKeyPair: RSAKeyPair): PKCSPaddingOracle {
    const rsaFunctions = initRSA();
    const modulusLengthBytes = Math.ceil(rsaKeyPair.publicKey.modulus.toString(2).length / 8);

    // with my implementation of RSA 00 02, 00 00 02 and 02 are going to be decrypted to the same string
    function isPlaintextPadded(ciphertext: Buffer): boolean {
        const plaintext = Buffer.alloc(modulusLengthBytes, 0x0);
        const decrypted = rsaFunctions.decryptMessage(ciphertext, rsaKeyPair.privateKey);
        decrypted.copy(plaintext, plaintext.length - decrypted.length);
        return plaintext[0] == 0x00 && plaintext[1] == 0x02;
    }

    return {
        isPlaintextPadded
    }
}

export function initPKCS1v15Padder(): PKCS1v15Padder {
    function pad(input: Buffer, length: number): Buffer {
        // padded input =  0x00 + 0x02 + eight non-zero bytes (at least) + 0x00 + input
        if ((input.length + 11) > length) {
            throw Error(`Input of length ${input.length} can not be padded to length ${length}`);
        }
        const padded = Buffer.alloc(length);
        padded[0] = 0x00;
        padded[1] = 0x02;
        const msgStart = padded.length - input.length;
        // generate "random" non-zero bytes
        const randomBytes = Buffer.alloc(msgStart - 2, 0xFF);
        randomBytes.copy(padded, 2);
        padded[msgStart - 1] = 0x00;
        input.copy(padded, padded.length - input.length);
        return padded;
    }

    function strip(input: Buffer): Buffer {
        const msgStart = input.indexOf(0x00, 2);
        if (input[0] != 0x00 || input[1] != 0x02 || msgStart === -1) {
            throw Error(`Input not PKCS1v1.5 padded`);
        }
        return input.slice(msgStart + 1, input.length);
    }

    return {
        pad,
        strip
    }
}

// Step 2.a: Starting the search.
export function bbSearchForS(
    lowerBound: BigNumber,
    pkcsCompliantCiphertext: Buffer,
    publicKeyUsed: RSAKey,
    oracle: PKCSPaddingOracle
): BigNumber {
    const pkcsCompliantCiphertextNum = new CryptoBigNumber(pkcsCompliantCiphertext.toString('hex'), 16);
    let siEncrypted: BigNumber, tamperedCiphertextNum: BigNumber, tamperedCiphertext: Buffer;
    for (let si = lowerBound.plus(1);; si = si.plus(1)) {
        siEncrypted = si.exponentiatedBy(publicKeyUsed.exponent, publicKeyUsed.modulus);
        tamperedCiphertextNum = pkcsCompliantCiphertextNum.times(siEncrypted).mod(publicKeyUsed.modulus);
        tamperedCiphertext = Buffer.from(tamperedCiphertextNum.toString(16), 'hex');
        if (oracle.isPlaintextPadded(tamperedCiphertext)) return si;
    }
}

// Step 2.c: Searching with one interval left.
export function bbSearchOneInterval(
    intervalLow: BigNumber,
    intervalHigh: BigNumber,
    publicKeyUsed: RSAKey,
    prevS: BigNumber,
    B: BigNumber,
    ciphertext: Buffer,
    oracle: PKCSPaddingOracle
): BigNumber {
    const ciphertextNum = new CryptoBigNumber(ciphertext.toString('hex'), 16);
    const bTimesS = intervalHigh.times(prevS);
    const riLow = two.times(bTimesS.minus(two.times(B))).dividedToIntegerBy(publicKeyUsed.modulus).plus(1);
    let siLow: BigNumber, siHigh: BigNumber, siEncrypted: BigNumber,
        tamperedCiphertextNum: BigNumber, tamperedCiphertext: Buffer, tamperedCiphertextStr: string;
    for (let ri = riLow;; ri = ri.plus(1)) {
        siLow = (two.times(B).plus(ri.times(publicKeyUsed.modulus))).dividedToIntegerBy(intervalHigh).plus(1);
        siHigh = (three.times(B).plus(ri.times(publicKeyUsed.modulus))).dividedToIntegerBy(intervalLow).plus(1);
        for (let si = siLow; si.lt(siHigh); si = si.plus(1)) {
            siEncrypted = si.exponentiatedBy(publicKeyUsed.exponent, publicKeyUsed.modulus);
            tamperedCiphertextNum = ciphertextNum.times(siEncrypted).mod(publicKeyUsed.modulus);
            tamperedCiphertextStr = tamperedCiphertextNum.toString(16);
            if (tamperedCiphertextStr.length % 2 === 1) tamperedCiphertextStr = '0'.concat(tamperedCiphertextStr);
            tamperedCiphertext = Buffer.from(tamperedCiphertextStr, 'hex');
            if (oracle.isPlaintextPadded(tamperedCiphertext)) {
                return si;
            }
        }
    }
}

// Step 3: Narrowing the set of solutions.
export function bbUpdateIntervals(
    intervals: BigNumber[][],
    prevS: BigNumber,
    B: BigNumber,
    publicKey: RSAKey
): BigNumber[][] {
    const twoB = two.times(B), threeB = three.times(B);
    let rLow: BigNumber, rHigh: BigNumber, intervalLow: BigNumber, intervalHigh: BigNumber, overlap: boolean;
    const updated: BigNumber[][] = [];
    for (const interval of intervals) {
        rLow = (interval[0].times(prevS).minus(threeB).plus(1)).dividedToIntegerBy(publicKey.modulus).plus(1);
        rHigh = (interval[1].times(prevS).minus(twoB)).dividedToIntegerBy(publicKey.modulus).plus(1);
        for (let ri = rLow; ri.lt(rHigh); ri = ri.plus(1)) {
            intervalLow = BigNumber.max(interval[0], twoB.plus(ri.times(publicKey.modulus)).dividedToIntegerBy(prevS).plus(1));
            intervalHigh = BigNumber.min(interval[1], (threeB.minus(1).plus(ri.times(publicKey.modulus))).dividedToIntegerBy(prevS));
            // detect overlap
            overlap = false;
            for (let intervalIdx = 0; intervalIdx < updated.length; intervalIdx++) {
                if (intervalHigh.gte(updated[intervalIdx][0]) && intervalLow.lte(updated[intervalIdx][1])) {
                    updated[intervalIdx] = [
                        BigNumber.min(intervalLow, updated[intervalIdx][0]), BigNumber.max(intervalHigh, updated[intervalIdx][1])
                    ];
                    overlap = true;
                }
            }
            if (!overlap) updated.push([intervalLow, intervalHigh]);
        }
    }
    return updated;
}

export function decryptPKCSPaddingOracleSimple(
    pkcsCompliantCiphertext: Buffer,
    publicKeyUsed: RSAKey,
    oracle: PKCSPaddingOracle,
): Buffer {
    const B = two.exponentiatedBy(240), twoB = two.times(B), threeB = three.times(B);
    let plaintextDecrypted = false;
    let intervals = [[twoB, threeB.minus(1)]];
    // we skip step 1 since we assume that original plaintext is PKCS padded
    const lowerBound = publicKeyUsed.modulus.dividedToIntegerBy(three.times(B));
    let s = bbSearchForS(lowerBound, pkcsCompliantCiphertext, publicKeyUsed, oracle);
    intervals = bbUpdateIntervals(intervals, s, B, publicKeyUsed);
    while (!plaintextDecrypted) {
        if (intervals[0][0].eq(intervals[0][1])) {
            plaintextDecrypted = true;
        } else {
            s = bbSearchOneInterval(intervals[0][0], intervals[0][1], publicKeyUsed, s, B, pkcsCompliantCiphertext, oracle);
            intervals = bbUpdateIntervals(intervals, s, B, publicKeyUsed);
        }
    }
    let plaintextStr = intervals[0][0].toString(16);
    if (plaintextStr.length % 2 != 0) plaintextStr = '0'.concat(plaintextStr);
    return Buffer.from(plaintextStr, 'hex');
}
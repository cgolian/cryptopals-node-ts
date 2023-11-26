import {BigNumber} from 'bignumber.js';
import {CryptoBigNumber} from './utils';
import * as crypto from 'crypto';

export interface RSAKey {
    exponent: BigNumber;
    modulus: BigNumber;
}

export interface RSAKeyPair {
    publicKey: RSAKey;
    privateKey: RSAKey;
}

export interface RSAFunctions {
    /**
     * Let n = p * q (p and q are random primes)
     * Your public key is [e, n]. Your private key is [d, n].
     * et = (p-1)*(q-1)
     * d = invmod(e, et)
     *
     * @param exponent (e)
     * @param modulusLength (length of n in bits)
     */
    generateKeyPair(exponent: number, modulusLength: number): RSAKeyPair;

    /**
     * Encryption: ciphertext = plaintext ^ publicKey.exponent mod publicKey.modulus
     *
     * @param plaintext
     * @param publicKey
     */
    encryptMessage(plaintext: Buffer, publicKey: RSAKey): Buffer;

    /**
     * Decryption: plaintext = ciphertext ^ privateKey.exponent mod privateKey.modulus
     *
     * @param ciphertext
     * @param privateKey
     */
    decryptMessage(ciphertext: Buffer, privateKey: RSAKey): Buffer;
}

export function modinv(num: BigNumber, modulus: BigNumber): BigNumber {
    const bigZero = new CryptoBigNumber(0);
    const bigOne = new CryptoBigNumber(1);
    let b0 = bigZero;
    let b1 = bigOne;
    let a = modulus;
    let b = num;
    let remainder = modulus;
    // gcd(a,b) = gcd(b,r) & gcd(a, 0) = a
    let quotient;
    let tmpB1;
    while (!b.eq(bigZero)) {
        remainder = a.mod(b);
        quotient = a.dividedToIntegerBy(b);
        tmpB1 = b1;
        b1 = b0.minus(quotient.times(b1));
        b0 = tmpB1;
        a = b;
        b = remainder;
    }
    if (!a.eq(bigOne)) {
        throw Error(`${num} is not invertible mod ${modulus}.`);
    }
    if (b0.lt(0)) {
        b0 = b0.plus(modulus);
    }
    return b0;
}

function getNumberOfRounds(bitLength: number): number {
    // shows how many different values must be chosen
    // in order to have a probability of less than 2^−80
    // that a composite is incorrectly detected as a prime
    if (bitLength < 250) return 11;
    if (bitLength < 300) return 9;
    if (bitLength < 400) return 6;
    if (bitLength < 500) return 5;
    return 3;
}

export function isProbablePrime(candidate: BigNumber): boolean {
    const candidateMinus2 = candidate.minus(2);
    const candidateMinus1 = candidate.minus(1);
    const one = new CryptoBigNumber(1);
    const roundsNr = getNumberOfRounds(candidate.toString(16).length * 4);
    let u = 0;
    let r = candidateMinus1;
    while (r.mod(2).eq(0)) {
        r = r.div(2);
        ++u;
    }
    let bigRand, a, z;
    for (let i = 0; i < roundsNr; i++) {
        bigRand = CryptoBigNumber.random();
        a = bigRand.times(candidateMinus2).plus(2).integerValue(BigNumber.ROUND_DOWN);
        z = a.exponentiatedBy(r, candidate);
        if (!z.eq(one) && !z.eq(candidateMinus1)) {
            for (let j = 0; j < u; j++) {
                z = z.exponentiatedBy(2, candidate);
                if (z.eq(1)) {
                    return false;
                }
            }
            if (!z.eq(candidateMinus1)) {
                return false;
            }
        }
    }
    return true;
}

export function generateRandomPrime(numberOfBits: number): BigNumber {
    let primeFound = false;
    let prime: BigNumber;
    while (!primeFound) {
        const randomBytes = crypto.randomBytes(numberOfBits / 8);
        randomBytes[0] |= 0x80;
        randomBytes[randomBytes.length - 1] |= 0x01;
        const candidate = new CryptoBigNumber(randomBytes.toString('hex'), 16);
        if (isProbablePrime(candidate)) {
            primeFound = true;
            prime = candidate;
            break;
        }
    }
    // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
    // @ts-ignore
    return prime;
}

export function initRSA(): RSAFunctions {
    function generateKeyPair(exponent: number, modulusLength: number): RSAKeyPair {
        const e = new CryptoBigNumber(exponent);
        let primesFound = false;
        let n: BigNumber, d: BigNumber;
        let p = generateRandomPrime(modulusLength / 2);
        let q = generateRandomPrime(modulusLength / 2);
        while (! primesFound) {
            n = p.times(q);
            const et = (p.minus(1)).times(q.minus(1));
            try {
                d = modinv(e, et);
                primesFound = true;
            } catch (e) {
                // e and (p-1)*(q-1) are not co-prime
                p = generateRandomPrime(modulusLength / 2);
                q = generateRandomPrime(modulusLength / 2);
            }
        }
        // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
        // @ts-ignore
        return { publicKey: { exponent: e, modulus: n }, privateKey: { exponent: d, modulus: n } };
    }

    function encryptMessage(plaintext: Buffer, publicKey: RSAKey): Buffer {
        const plaintextNum = new CryptoBigNumber(plaintext.toString('hex'), 16);
        const ciphertextNum = plaintextNum.exponentiatedBy(publicKey.exponent, publicKey.modulus);
        let ciphertextStr = ciphertextNum.toString(16);
        if (ciphertextStr.length % 2 != 0) {
            ciphertextStr = '0'.concat(ciphertextStr);
        }
        return Buffer.from(ciphertextStr, 'hex');
    }

    function decryptMessage(ciphertext: Buffer, privateKey: RSAKey): Buffer {
        const ciphertextNum = new CryptoBigNumber(ciphertext.toString('hex'), 16);
        const plaintextNum = ciphertextNum.exponentiatedBy(privateKey.exponent, privateKey.modulus);
        let plaintextNumStr = plaintextNum.toString(16);
        if (plaintextNumStr.length % 2 != 0) {
            plaintextNumStr = '0'.concat(plaintextNumStr);
        }
        return Buffer.from(plaintextNumStr, 'hex');
    }

    return {
        generateKeyPair,
        encryptMessage: encryptMessage,
        decryptMessage: decryptMessage
    };
}
import {initRSA, RSAKey, RSAKeyPair} from '../set5/challenge39';
import { CryptoBigNumber } from '../set5/utils';
import { BigNumber } from 'bignumber.js';
import {Decimal} from 'decimal.js';

export interface RSAParityOracle {
    /**
     * Return true if RSA decrypted plaintext is even
     * @param ciphertext
     */
    isPlaintextEven(ciphertext: Buffer): boolean;
}

export function initRSAParityOracle(rsaKeyPair: RSAKeyPair): RSAParityOracle {
    const rsaFunctions = initRSA();

    function isPlaintextEven(ciphertext: Buffer): boolean {
        const plaintext = rsaFunctions.decryptMessage(ciphertext, rsaKeyPair.privateKey);
        const plaintextNum = new CryptoBigNumber(plaintext.toString('hex'), 16);
        return plaintextNum.mod(2).isEqualTo(0);
    }

    return {
        isPlaintextEven
    }
}

export function binaryLogarithm(num: BigNumber): number {
    const decModulus = new Decimal(num.toString(10));
    const result = Decimal.log2(decModulus);
    return Number.parseInt(result.ceil().toString());
}

/**
 * Decrypt RSA encrypted unpadded ciphertext using a "parity oracle"
 * @param ciphertext ciphertext going to be decrypted
 * @param publicKey public key
 * @param rsaParityOracle parity oracle
 */
export function decryptRSACiphertextWithParityOracle(ciphertext: Buffer, publicKey: RSAKey, rsaParityOracle: RSAParityOracle): Buffer {
    let upper = new CryptoBigNumber(publicKey.modulus);
    let lower = new CryptoBigNumber(0);
    const bigTwo = new CryptoBigNumber(2);
    const encryptedTwo = bigTwo.exponentiatedBy(publicKey.exponent, publicKey.modulus);
    let ciphertextNum = new CryptoBigNumber(ciphertext.toString('hex'), 16);
    let mulCiphertext: Buffer;
    let mid;
    let result;
    let ciphertextNumStr;
    const iters = binaryLogarithm(publicKey.modulus);
    for (let i = 0; i < iters; i++) {
        ciphertextNum = ciphertextNum.times(encryptedTwo).mod(publicKey.modulus);
        ciphertextNumStr = ciphertextNum.toString(16);
        if (ciphertextNumStr.length % 2 != 0) ciphertextNumStr = '0'.concat(ciphertextNumStr);
        mulCiphertext = Buffer.from(ciphertextNumStr,'hex');
        result = rsaParityOracle.isPlaintextEven(mulCiphertext);
        mid = upper.plus(lower).div(2);
        if (result) {
            upper = mid;
        } else {
            lower = mid;
        }
    }
    upper = upper.integerValue(CryptoBigNumber.ROUND_DOWN);
    let upperNumStr = upper.toString(16);
    if (upperNumStr.length % 2 != 0) upperNumStr = '0'.concat(upperNumStr);
    return Buffer.from(upperNumStr,'hex');
}
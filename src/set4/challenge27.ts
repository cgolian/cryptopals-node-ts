import {aes128CbcDecrypt, aes128CbcEncrypt} from '../set2/challenge10';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {BitArray} from '../set1/challenge1';
import {XORBitArrays} from '../set1/challenge2';

export function aes128CbcEncryptWKeyAsIV(plaintext: Buffer, key: Buffer): Buffer {
    return aes128CbcEncrypt(plaintext, key, key);
}

export function aes128CbcDecryptWKeyAsIV(ciphertext: Buffer, key: Buffer): Buffer {
    return aes128CbcDecrypt(ciphertext, key, key);
}

export interface RevealingPlaintextValidationOracle {
    /**
     * validate ciphertext & throw error in case wrong encoding is used
     * @param ciphertext
     */
    validate(ciphertext: Buffer): void;
}

export function initRevealingPlaintextValidationOracle(key: Buffer): RevealingPlaintextValidationOracle {
    function validate(ciphertext: Buffer): void {
        const plaintext = aes128CbcDecryptWKeyAsIV(ciphertext, key);
        if (plaintext.some(byte => byte > 127)) {
            throw Error(`Invalid encoding: ${plaintext.toString('hex')}`);
        }
    }
    return {
        validate
    };
}

/**
 * Recover key used in CBC encryption of the ciphertext using validation oracle
 *
 * Explanation:
 * ciphertext input (c1 c2 c3 c4) (0x0 0x0 0x0 0x0) (c1 c2 c3 c4)
 * (p1 p2 p3 p4) = aes_128_cbc(c1 c2 c3 c4) XOR key
 * (p9 p10 p11 p12) = aes_128_cbc(c1 c2 c3 c4) XOR (0x0 0x0 0x0 0x0)
 * (p1 p2 p3 p4) XOR (p9 p10 p11 p12) = aes_128_cbc(c1 c2 c3 c4) XOR key XOR aes_128_cbc(c1 c2 c3 c4) XOR (0x0 0x0 0x0 0x0)
 * (p1 p2 p3 p4) XOR (p9 p10 p11 p12) = key XOR (0x0 0x0 0x0 0x0)
 * (p1 p2 p3 p4) XOR (p9 p10 p11 p12) = key
 *
 * @param ciphertext CBC encrypted ciphertext
 * @param validationOracle validation oracle revealing plaintext
 */
export function recoverKeyUsingRevealingPlaintextValidationOracle(
    ciphertext: Buffer,
    validationOracle: RevealingPlaintextValidationOracle
): Buffer {
    const firstCiphertextBlock = ciphertext.slice(0, AES_128_BLOCK_LENGTH_BYTES);
    const zeroes = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES, 0x0);
    try {
        const modifiedCiphertext = Buffer.concat([firstCiphertextBlock, zeroes, firstCiphertextBlock]);
        validationOracle.validate(modifiedCiphertext);
    } catch (e) {
        const errorMsgStart = 'Error: Invalid encoding: ';
        const hexPlaintext = (e as string).toString().substr(errorMsgStart.length);
        const plaintext = Buffer.from(hexPlaintext, 'hex');
        const firstPlaintextBlock = plaintext.slice(0, AES_128_BLOCK_LENGTH_BYTES);
        const thirdPlaintextBlock = plaintext.slice(2 * AES_128_BLOCK_LENGTH_BYTES, 3 * AES_128_BLOCK_LENGTH_BYTES);
        return BitArray.toBuffer(
            XORBitArrays(BitArray.fromBuffer(firstPlaintextBlock), BitArray.fromBuffer(thirdPlaintextBlock))
        );
    }
    throw Error(`Could not recover key`);
}
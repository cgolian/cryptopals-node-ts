import {aes128CtrDecrypt, aes128CtrEncrypt} from '../set3/challenge18';
import {BitArray} from '../set1/challenge1';
import {XORBitArrays} from '../set1/challenge2';

export interface Aes128CtrEditOracle {
    /**
     * Re-encrypt decrypted plaintext modified at offset with edit
     * @param ciphertext ciphertext
     * @param offset offset in the plaintext
     * @param edit change to be made
     */
    edit(ciphertext: Buffer, offset: number, edit: Buffer): Buffer;
}

export function initAes128CtrEditOracle(key: Buffer, nonce: Buffer): Aes128CtrEditOracle {
    function aes128CtrEdit(ciphertext: Buffer, offset: number, edit: Buffer): Buffer {
        if (offset < 0 || offset > ciphertext.length) {
            throw Error(`Invalid offset`);
        }
        const plaintext = aes128CtrDecrypt(ciphertext, key, nonce);
        edit.copy(plaintext, offset, 0, edit.length);
        return aes128CtrEncrypt(plaintext, key, nonce);
    }

    return {
        edit: aes128CtrEdit
    }
}

/**
 * Recover plaintext using 'edit oracle'
 *
 * in AES CTR mode:
 * ciphertext = plaintext XOR AES_128_ECB(keystream, key)
 * encrypted_zeros = zeros XOR AES_128_ECB(keystream, key)
 *
 * ciphertext XOR encrypted_zeros = plaintext XOR AES_128_ECB(keystream, key) XOR zeros XOR AES_128_ECB(keystream, key)
 * = plaintext XOR zeros = plaintext
 *
 * @param ciphertext
 * @param oracle
 */
export function recoverPlaintextUsingAesCtrEditOracle(
    ciphertext: Buffer,
    oracle: Aes128CtrEditOracle
): Buffer {
    const zeros = Buffer.alloc(ciphertext.length).fill(0x0);
    const encryptedZeros = oracle.edit(ciphertext, 0, zeros);
    return BitArray.toBuffer(XORBitArrays(BitArray.fromBuffer(ciphertext), BitArray.fromBuffer(encryptedZeros)));
}

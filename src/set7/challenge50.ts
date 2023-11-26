import {aes128CbcDecrypt, aes128CbcEncrypt} from '../set2/challenge10';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {XORBitArrays} from '../set1/challenge2';
import {BitArray} from '../set1/challenge1';

/**
 * Pads plaintext with additional input so that CBC MAC of the resulting string == original MAC
 * @param originalMAC message authentication code
 * @param plaintext plaintext which is going to be padded
 * @param iv initialization vector used when computing CBC MAC
 * @param key key used when computing CBC MAC
 */
export function padPlaintextToMatchCbcMac(originalMAC: Buffer, plaintext: Buffer, iv: Buffer, key: Buffer): Buffer {
    const encrypted = aes128CbcEncrypt(plaintext, iv, key);
    const lastEncryptedBlock = encrypted.slice(encrypted.length - AES_128_BLOCK_LENGTH_BYTES);
    const decryptedMAC = aes128CbcDecrypt(originalMAC, iv, key);
    const additional = XORBitArrays(BitArray.fromBuffer(lastEncryptedBlock), BitArray.fromBuffer(decryptedMAC));
    return Buffer.concat([plaintext, BitArray.toBuffer(additional)]);
}
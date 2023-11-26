import {breakSingleByteXOR, SingleByteXORDecryptionResult} from './challenge3';

type SingleByteXORDecryption = {
    encryptedString: string;
    decryptionInfo: SingleByteXORDecryptionResult;
}

/**
 * Detect & decrypt ciphertext encrypted with single byte XOR
 * @param ciphertexts array of ciphertexts
 */
export function detectSingleByteXOREncryptedString(ciphertexts: ReadonlyArray<string>): SingleByteXORDecryption {
    let encryptedString = '';
    let result: SingleByteXORDecryptionResult = {
        score: Number.MAX_SAFE_INTEGER,
        keyByte: 0x00,
        plaintext: Buffer.alloc(1)
    };
    let currentScore: SingleByteXORDecryptionResult;
    ciphertexts.forEach(ciphertext => {
        currentScore = breakSingleByteXOR(ciphertext);
        if (currentScore.score < result.score) {
            result = currentScore;
            encryptedString = ciphertext;
        }
    });
    return {
        encryptedString: encryptedString,
        decryptionInfo: result
    };
}
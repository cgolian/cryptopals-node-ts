import {BitArray} from './challenge1';
import {XORBitArrays} from './challenge2';

interface AsciiFrequencyTable {
    [key: string]: number;
}

const characterFrequencyLookupTable: AsciiFrequencyTable = {
    ' ': 17.1662, '!': 0.0072, '"': 0.2442, '#': 0.0179, '$': 0.0561, '%': 0.016, '&': 0.0226, '\'': 0.2447,
    '(': 0.2178, ')': 0.2233, '*': 0.0628, '+': 0.0215, ',': 0.7384, '-': 1.3734, '.': 1.5124, '/': 0.1549, '0': 0.5516,
    '1': 0.4594, '2': 0.3322, '3': 0.1847, '4': 0.1348, '5': 0.1663, '6': 0.1153, '7': 0.103, '8': 0.1054, '9': 0.1024,
    ':': 0.4354, ';': 0.1214, '<': 0.1225, '=': 0.0227, '>': 0.1242, '?': 0.1474, '@': 0.0073, 'A': 0.3132, 'B': 0.2163,
    'C': 0.3906, 'D': 0.3151, 'E': 0.2673, 'F': 0.1416, 'G': 0.1876, 'H': 0.2321, 'I': 0.3211, 'J': 0.1726, 'K': 0.0687,
    'L': 0.1884, 'M': 0.3529, 'N': 0.2085, 'O': 0.1842, 'P': 0.2614, 'Q': 0.0316, 'R': 0.2519, 'S': 0.4003, 'T': 0.3322,
    'U': 0.0814, 'V': 0.0892, 'W': 0.2527, 'X': 0.0343, 'Y': 0.0304, 'Z': 0.0076, '[': 0.0086, '\\': 0.0016, ']': 0.0088,
    '^': 0.0003, '_': 0.1159, '`': 0.0009, 'a': 5.188, 'b': 1.0195, 'c': 2.1129, 'd': 2.5071, 'e': 8.5771, 'f': 1.3725,
    'g': 1.5597, 'h': 2.7444, 'i': 4.9019, 'j': 0.0867, 'k': 0.6753, 'l': 3.175, 'm': 1.6437, 'n': 4.9701, 'o': 5.7701,
    'p': 1.5482, 'q': 0.0747, 'r': 4.2586, 's': 4.3686, 't': 6.37, 'u': 2.0999, 'v': 0.8462, 'w': 1.3034, 'x': 0.195,
    'y': 1.133, 'z': 0.0596, '{': 0.0026, '|': 0.0007, '}': 0.0026, '~': 0.0003,
};

function initializeCharacterFrequencyTable(): AsciiFrequencyTable {
    return {
        ' ': 0, '!': 0, '"': 0, '#': 0, '$': 0, '%': 0, '&': 0, '\'': 0,
        '(': 0, ')': 0, '*': 0, '+': 0, ',': 0, '-': 0, '.': 0, '/': 0, '0': 0,
        '1': 0, '2': 0, '3': 0, '4': 0, '5': 0, '6': 0, '7': 0, '8': 0, '9': 0,
        ':': 0, ';': 0, '<': 0, '=': 0, '>': 0, '?': 0, '@': 0, 'A': 0, 'B': 0,
        'C': 0, 'D': 0, 'E': 0, 'F': 0, 'G': 0, 'H': 0, 'I': 0, 'J': 0, 'K': 0,
        'L': 0, 'M': 0, 'N': 0, 'O': 0, 'P': 0, 'Q': 0, 'R': 0, 'S': 0, 'T': 0,
        'U': 0, 'V': 0, 'W': 0, 'X': 0, 'Y': 0, 'Z': 0, '[': 0, '\\': 0, ']': 0,
        '^': 0, '_': 0, '`': 0, 'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0,
        'g': 0, 'h': 2, 'i': 0, 'j': 0, 'k': 0, 'l': 0, 'm': 0, 'n': 0, 'o': 0,
        'p': 0, 'q': 0, 'r': 0, 's': 0, 't': 0, 'u': 0, 'v': 0, 'w': 0, 'x': 0,
        'y': 0, 'z': 0, '{': 0, '|': 0, '}': 0, '~': 0,
    };
}

function computeFrequencyScore(plaintext: BitArray): number {
    const frequencyTable = initializeCharacterFrequencyTable();
    let score = 0;
    for (let idx = 0; idx < plaintext.length; idx += 8) {
        const endIdx = idx + 7 >= plaintext.length ? plaintext.length - 1 : idx + 7;
        const charCode = plaintext.getWord(idx, endIdx);
        const char = String.fromCharCode(charCode);
        if (char in characterFrequencyLookupTable) {
            frequencyTable[char] = frequencyTable[char] + 1;
        } else {
            // characters other than whitespaces and newlines get a penalty
            if (!/\s/.test(char) && char !== '\n') {
                // penalty
                score += 10;
            }
        }
    }
    // normalize number of occurrences
    Object.keys(frequencyTable).forEach(char => {
        frequencyTable[char] = (frequencyTable[char] / (plaintext.length / 8)) * 100;
    });
    // calculate score
    Object.keys(frequencyTable).forEach(char => {
        if (characterFrequencyLookupTable[char] !== 0 || characterFrequencyLookupTable[char] !== 0) {
            const val =
                Math.pow(frequencyTable[char] - characterFrequencyLookupTable[char], 2) /
                (characterFrequencyLookupTable[char] + frequencyTable[char]);
            score += val;
        }
    });
    return score;
}

export interface SingleByteXORDecryptionResult {
    plaintext: Buffer;
    keyByte: number;
    score: number;
}

/**
 * Decrypt hexadecimal ciphertext encrypted with XOR using single byte key
 * @param hexCiphertext string in hexadecimal format
 */
export function breakSingleByteXOR(hexCiphertext: string): SingleByteXORDecryptionResult {
    const inputBitArray = BitArray.fromHexString(hexCiphertext);
    let currentPlaintext, currentScore, result, keyByte, bestScore = Number.MAX_SAFE_INTEGER;
    const keyLength = hexCiphertext.length / 2;
    // initialize key array
    const singleByteKey = '00'.repeat(keyLength);
    const singleByteKeyBitArray = BitArray.fromHexString(singleByteKey);
    for (let idx = 0; idx < 256; idx++) {
        singleByteKeyBitArray.fillWithByte(idx);
        currentPlaintext = XORBitArrays(singleByteKeyBitArray, inputBitArray);
        currentScore = computeFrequencyScore(currentPlaintext);
        if (currentScore < bestScore) {
            keyByte = idx;
            result = currentPlaintext;
            bestScore = currentScore;
        }
    }
    return {
        keyByte: keyByte as number,
        plaintext: BitArray.toBuffer(result as BitArray),
        score: bestScore
    };
}
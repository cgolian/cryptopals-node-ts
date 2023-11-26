import {BitArray} from './challenge1';
import {breakSingleByteXOR} from './challenge3';
import {XORBitArrays} from './challenge2';
import {createXORKey} from './challenge5';

type Keysize = {
    keysize: number;
    distance: number;
};

export function hamming(array1: BitArray, array2: BitArray): number {
    if (array1.length != array2.length) {
        throw Error(`Arrays are of different length`);
    }
    let distance = 0;
    for (let idx = 0; idx < array1.length; idx++) {
        if (array1.getBit(idx) != array2.getBit(idx)) distance++;
    }
    return distance;
}

// calculate potential keysize of key used to encrypt ciphertext
function calculatePotentialKeysizes(contents: Buffer): Array<Keysize> {
    const keysizes: Array<Keysize> = [];
    for (let KEYSIZE = 2; KEYSIZE < 40; KEYSIZE++) {
        // for this KEYSIZE take first KEYSIZE worth of bytes...
        const first = BitArray.fromBuffer(contents.slice(0, 4 * KEYSIZE));
        // ...second KEYSIZE worth of bytes
        const second = BitArray.fromBuffer(contents.slice(4 * KEYSIZE, 8 * KEYSIZE));
        // and compute their normalized edit distance
        const normalized = hamming(first, second) / (4 * KEYSIZE);
        keysizes.push({ keysize: KEYSIZE, distance: normalized });
    }
    return keysizes.sort((keysizeObj1, keysizeObj2) => {
        return keysizeObj1.distance - keysizeObj2.distance;
    });
}

// split content into blocks of KEYSIZE length
export function splitIntoBlocks(
    content: Buffer,
    blockLength: number
): Array<Buffer> {
    const blocks: Array<Buffer> = [];
    for (let i = 0; i < content.length; i += blockLength) {
        const block = content.slice(i, i + blockLength);
        blocks.push(block);
    }
    return blocks;
}

export function transposeBlocks(blocks: ReadonlyArray<Buffer>, transposedCount: number): Array<Buffer> {
    const contentLength = blocks.reduce((prev, block) => prev + block.length, 0);
    if ((contentLength % transposedCount) != 0) {
        throw Error(`Blocks cannot be transposed`);
    }
    const blockLength = contentLength / transposedCount;
    const transposedBlocks: Array<Buffer> = [];
    // create buffers
    for (let i = 0; i < transposedCount; i++) {
        transposedBlocks.push(Buffer.alloc(blockLength));
    }
    // iterate over blocks and add i-th character to i-th block
    blocks.forEach((block: Buffer, blockNr: number) => {
        block.forEach((byte: number, idx: number) => {
            const modIdx = idx % transposedCount;
            transposedBlocks[modIdx][blockNr] = block[idx];
        });
    });
    return transposedBlocks;
}

/**
 * Decrypt ciphertext encrypted by XORing plaintext with repeating key
 * @param ciphertext ciphertext
 */
export function decryptRepeatingKeyXOR(ciphertext: Buffer): Buffer {
    const keysizes = calculatePotentialKeysizes(ciphertext);
    const firstKeysize = keysizes[0].keysize;
    const transposedBlocks = transposeBlocks(
        splitIntoBlocks(ciphertext, firstKeysize),
        firstKeysize
    );
    // solve the blocks as single byte XORs
    const keyBytes = Buffer.alloc(firstKeysize);
    transposedBlocks.forEach((transposedBlock: Buffer, blockIdx: number) => {
        const result = breakSingleByteXOR(transposedBlock.toString('hex'));
        keyBytes[blockIdx] = result.keyByte;
    });
    // decipher ciphertext using key
    const extendedKey = createXORKey(keyBytes, ciphertext.length);
    const result = XORBitArrays(BitArray.fromBuffer(ciphertext), BitArray.fromBuffer(extendedKey));
    return BitArray.toBuffer(result);
}
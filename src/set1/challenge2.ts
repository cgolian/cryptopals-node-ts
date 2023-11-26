import {BitArray} from './challenge1';

export function XORBitArrays(input1: BitArray, input2: BitArray): BitArray {
    if ((input1.length != input2.length)) {
        throw Error(`Length differs.`);
    }
    const result = new BitArray(input1.length);
    for (let bitIdx = 0; bitIdx < input1.length; bitIdx++) {
        const xoredBit = input1.getBit(bitIdx) ^ input2.getBit(bitIdx);
        if (xoredBit) result.setBit(bitIdx);
    }
    return result;
}

/**
 * XOR two hexadecimal strings
 * @param hexInput1 string in hexadecimal format
 * @param hexInput2 string in hexadecimal format
 */
export function XORHexStrings(hexInput1: string, hexInput2: string): string {
    const bitResult = XORBitArrays(BitArray.fromHexString(hexInput1), BitArray.fromHexString(hexInput2));
    return BitArray.toHexString(bitResult);
}
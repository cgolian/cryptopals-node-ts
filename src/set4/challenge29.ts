import Sha1 from './sha1';
import {computeMACwSHA1, verifyMACwSHA1} from './challenge28';

type Endianness = 'BE' | 'LE';
/**
 * Pad message in the same way as done internally by SHA1/MD4 functions
 *
 * @param msg message
 * @param blockSizeBits block size in bits
 * @param msgSizeEndian if 'BE' message length is stored as big endian, if 'LE' as little endian
 */
export function padMessageMD(msg: Buffer, blockSizeBits: number, msgSizeEndian: Endianness): Buffer {
    if (!Number.isSafeInteger(msg.length * 8)) {
        throw Error(`Message cannot be padded`);
    }
    const nrOfBlocks = Math.floor(((msg.length * 8) + 1 + 64) / blockSizeBits) + 1;
    const padded = Buffer.alloc(nrOfBlocks * (blockSizeBits / 8), 0x0);
    msg.copy(padded);
    padded[msg.length] = 0x80; // 1 bit
    if (msgSizeEndian === 'BE') { // SHA1 implementation is storing message length in bits as BE, MD4 as LE
        padded.writeUInt32BE(msg.length * 8, padded.length - 4);
    } else {
        padded.writeInt32LE(msg.length * 8, padded.length - 8);
    }
    return padded;
}

type HashFnType = 'sha1' | 'md4';
export function restoreHashFunctionState(hash: Buffer, hashFnType: HashFnType): Array<number> {
    const state = [];
    if (hashFnType === 'sha1') {
        for (let i = 0; i < 20; i += 4) state.push(hash.slice(i, i + 4).readIntBE(0, 4));
    } else {
        for (let i = 0; i < 16; i += 4) state.push(hash.slice(i, i + 4).readIntLE(0, 4));
    }
    return state;
}

/**
 * Hash message with additional input by restoring its state using previous hash.
 *
 * @param msg message
 * @param mac message authentication code
 * @param keyLength length of the key used in secret prefix MAC
 * @param additionalInput additional input
 */
function hashAdditionalInputWSHA1(
    msg: Buffer,
    mac: Buffer,
    keyLength: number,
    additionalInput: Buffer
): Buffer {
    const sha1State = restoreHashFunctionState(mac, 'sha1');
    const keyPlaceholder = Buffer.alloc(keyLength, 0x0);
    const msgWKey = padMessageMD(Buffer.concat([keyPlaceholder, msg]), 512, 'BE');
    const tamperedLengthBits = (msgWKey.length + additionalInput.length) * 8;
    const additionalMAC = Sha1.hash(additionalInput.toString('hex'), {
        msgFormat: 'hex-bytes',
        outFormat: 'hex',
        state: sha1State,
        desiredLength: tamperedLengthBits
    });
    return Buffer.from(additionalMAC, 'hex');
}

export interface SecretPrefixOracle {
    computeMAC(msg: Buffer): Buffer;
    verifyMAC(msg: Buffer, mac: Buffer): boolean;
}

export function initSHA1SecretPrefixOracle(secretKey: Buffer): SecretPrefixOracle {
    return {
        computeMAC: (msg: Buffer): Buffer => computeMACwSHA1(msg, secretKey),
        verifyMAC: (msg: Buffer, mac: Buffer): boolean => verifyMACwSHA1(msg, mac, secretKey)
    }
}

/**
 * Prepare tampered input:
 * key placeholder || message || original padding || additional input
 *
 * @param keyPlaceholder key placeholder
 * @param msg message
 * @param additionalInput additional input
 * @param msgSizeEndian endian
 */
export function prepareTamperedInput(keyPlaceholder: Buffer, msg: Buffer, additionalInput: Buffer, msgSizeEndian: Endianness): Buffer {
    const padded = padMessageMD(Buffer.concat([keyPlaceholder, msg]), 512, msgSizeEndian);
    return Buffer.concat([padded.slice(keyPlaceholder.length, padded.length), additionalInput]);
}

export type ForgedSecretPrefixMAC = {
    input: Buffer;
    mac: Buffer;
    keyLength: number;
}

export function forgeSecretPrefixMACwSHA1(
    msg: Buffer,
    mac: Buffer,
    additionalInput: Buffer,
    oracle: SecretPrefixOracle
): ForgedSecretPrefixMAC {
    let keyPlaceholder: Buffer;
    let forgedMAC;
    let tamperedMsg;
    // 100 is here just a guess
    for (let i = 1; i < 100; i++) {
        keyPlaceholder = Buffer.alloc(i, 0x0);
        forgedMAC = hashAdditionalInputWSHA1(msg, mac, keyPlaceholder.length, additionalInput);
        tamperedMsg = prepareTamperedInput(keyPlaceholder, msg, additionalInput, 'BE');
        if (oracle.verifyMAC(tamperedMsg, forgedMAC)) {
            return {
                input: tamperedMsg,
                mac: forgedMAC,
                keyLength: keyPlaceholder.length
            };
        }
    }
    throw Error(`Could not forge input`);
}
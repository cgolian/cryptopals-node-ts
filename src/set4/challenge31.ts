import Sha1 from './sha1';
import {XORBitArrays} from '../set1/challenge2';
import {BitArray} from '../set1/challenge1';

// SHA1 hash with hex input and hex output
function hexSHA1(buffer: Buffer): Buffer {
    return Buffer.from(Sha1.hash(buffer.toString('hex'), {
        msgFormat: 'hex-bytes',
        outFormat: 'hex'
    }), 'hex');
}
export function computeHMACwSHA1(msg: Buffer, key: Buffer): Buffer {
    const blockSizeBytes = 64;
    const ipad = BitArray.fromBuffer(Buffer.alloc(blockSizeBytes, 0x36));
    const opad = BitArray.fromBuffer(Buffer.alloc(blockSizeBytes, 0x5c));
    const blockSizedKey = Buffer.alloc(blockSizeBytes, 0x0);
    if (key.length > blockSizeBytes) {
        const keyHash = hexSHA1(key);
        keyHash.copy(blockSizedKey);
    } else {
        key.copy(blockSizedKey);
    }
    const xorO = BitArray.toBuffer(XORBitArrays(BitArray.fromBuffer(blockSizedKey), opad));
    const xorI = BitArray.toBuffer(XORBitArrays(BitArray.fromBuffer(blockSizedKey), ipad));
    const xorIwMsg = Buffer.concat([xorI, msg]);
    const hashIwMsg = hexSHA1(xorIwMsg);
    const xorOwMsg = Buffer.concat([xorO, hashIwMsg]);
    return hexSHA1(xorOwMsg);
}

function sleep(millis: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, millis));
}

export async function insecureCompare(buf1: Buffer, buf2: Buffer): Promise<boolean> {
    for (let idxB1 = 0; idxB1 < buf1.length; idxB1++) {
        if (buf1[idxB1] != buf2[idxB1]) {
            return false;
        }
        await sleep(50);
    }
    return true;
}
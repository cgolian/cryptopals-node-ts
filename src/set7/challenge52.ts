import {padBlockPKCS7} from '../set2/challenge9';
import {
    AES_128_BLOCK_LENGTH_BYTES
} from '../set1/challenge7';
import {splitIntoBlocks} from '../set1/challenge6';
import * as crypto from 'crypto';
import { padMessageMD } from '../set4/challenge29';

export type MsgPair = {
    msg1: Buffer;
    msg2: Buffer;
};

export type CollisionPair = {
    msgPair: MsgPair;
    digest: Buffer;
};

type ComputeDigestFn = (state: Buffer, input: Buffer) => Buffer;
export type HashFn = ComputeDigestFn;
export type CompressionFn = ComputeDigestFn;

export function createCustomMDCompressionFunction(digestSizeInBytes: number): CompressionFn {
    if (digestSizeInBytes > AES_128_BLOCK_LENGTH_BYTES) throw Error(`Unsupported digest size`);
    return function customMDCompressionFunction(state: Buffer, input: Buffer): Buffer {
        const key = padBlockPKCS7(state, AES_128_BLOCK_LENGTH_BYTES);
        const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
        const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
        return encrypted.slice(0, digestSizeInBytes);
    }
}

export function createCustomMDHashFunction(compressionFn: CompressionFn): HashFn {
    return function customMDHash(state: Buffer, input: Buffer): Buffer {
        const padded = padMessageMD(input, AES_128_BLOCK_LENGTH_BYTES * 8, 'BE');
        const blocks = splitIntoBlocks(padded, AES_128_BLOCK_LENGTH_BYTES);
        let digest = state;
        for (let bIdx = 0; bIdx < blocks.length; bIdx++) {
            digest = compressionFn(digest, blocks[bIdx]);
        }
        return digest;
    }
}

/**
 * Find a pair of messages (one block in length) having the same digest
 * @param digestSizeInBytes digest size in bytes
 * @param initialState initial state
 * @param compressionFn compression function used in computing the digest
 */
export function findCollisionPair(
    digestSizeInBytes: number,
    initialState: Buffer,
    compressionFn: CompressionFn
): CollisionPair {
    const q = Math.pow(2, Math.ceil((digestSizeInBytes * 8) / 2));
    let collision: CollisionPair | null = null;
    while (!collision) {
        // generate random messages
        const msgs = Array(q);
        for (let i = 0; i <= q; i++) {
            msgs[i] = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
        }
        // compute their hashes
        const digestDict: { [key: string]: string } = {};
        let digest: Buffer, hexDigest: string, curMsgHex: string, matchingDigestMsgHex: string;
        for (let i = 0; i < q; i++) {
            digest = compressionFn(initialState, msgs[i]);
            hexDigest = digest.toString('hex');
            curMsgHex = msgs[i].toString('hex');
            // and look for collisions
            if (digestDict[hexDigest]) {
                matchingDigestMsgHex = digestDict[hexDigest];
                if (matchingDigestMsgHex != curMsgHex) {
                    collision = {
                        msgPair: {
                            msg1: Buffer.from(curMsgHex, 'hex'),
                            msg2: Buffer.from(matchingDigestMsgHex, 'hex')
                        },
                        digest: Buffer.from(hexDigest, 'hex')
                    }
                    break;
                }
            }
            digestDict[hexDigest] = curMsgHex;
        }
    }
    return collision;
}

export type Collisions = {
    messages: Array<Buffer>;
    state: Buffer;
}

/**
 * Generate 2^t collisions for given hash function
 * @param t
 * @param digestSizeInBytes digest size
 * @param compressionFn compression function
 */
export function generateCollisions(
    t: number,
    digestSizeInBytes: number,
    compressionFn: CompressionFn
): Collisions {
    const collisionPairs: CollisionPair[] = Array(t);
    const initialState = crypto.randomBytes(digestSizeInBytes);
    let collisionPair: CollisionPair;
    // make t calls to the "collision finding machine"
    let state = initialState;
    for (let i = 0; i < t; i++) {
        collisionPair = findCollisionPair(digestSizeInBytes, state, compressionFn);
        // save blocks b_i and b'_i
        collisionPairs[i] = collisionPair;
        state = collisionPair.digest;
    }
    // construct 2^t messages from stored blocks
    const numOfMsgs = Math.pow(2, t), generatedMsgs: Buffer[] = Array(numOfMsgs), msg: Buffer[] = Array(t);
    let block1: Buffer, block2: Buffer;
    for (let i = 0; i < numOfMsgs; i++) {
        for (let j = 0; j < t; j++) {
            block1 = collisionPairs[j].msgPair.msg1;
            block2 = collisionPairs[j].msgPair.msg2;
            msg[j] = (i & (1 << j)) ? block1 : block2;
        }
        generatedMsgs[i] = Buffer.concat(msg);
    }
    return {
        messages: generatedMsgs,
        state: initialState
    };
}

export type DigestDictionary = {
    [hexDigest: string]: string;
}

export function findCollisionPairForCascadedMDHashFunction(
    cheapMDCompressionFn: CompressionFn,
    cheapMDHashFnDigestSizeBytes: number,
    expensiveMDCompressionFn: CompressionFn,
    expensiveMDHashFnDigestSizeBytes: number,
): {
    msgPair: MsgPair;
    state: Buffer;
    collisionFnCalls: number;
} {
    let msgPair: MsgPair | null = null, state: Buffer | null = null;
    let collisions: Collisions, hashesDict: DigestDictionary;
    let collisionFnCalls = 0, t;
    while (!msgPair || !state) {
        t = Math.ceil((expensiveMDHashFnDigestSizeBytes * 8) / 2);
        collisions = generateCollisions(t, cheapMDHashFnDigestSizeBytes, cheapMDCompressionFn);
        hashesDict = {};
        collisionFnCalls += t;
        let digest: Buffer, hexDigest: string, blocks: Buffer[];
        for (let msgIdx = 0; msgIdx < collisions.messages.length; msgIdx++) {
            // compute digest using "expensive" compression fn
            blocks = splitIntoBlocks(collisions.messages[msgIdx], AES_128_BLOCK_LENGTH_BYTES);
            digest = collisions.state;
            for (let bIdx = 0; bIdx < blocks.length; bIdx++) {
                digest = expensiveMDCompressionFn(digest, blocks[bIdx]);
            }
            hexDigest = digest.toString('hex');
            if (hashesDict[hexDigest]) {
                state = collisions.state;
                msgPair = { msg1: Buffer.from(hashesDict[hexDigest], 'hex'), msg2: collisions.messages[msgIdx] };
                break;
            }
            hashesDict[hexDigest] = collisions.messages[msgIdx].toString('hex');
        }
    }
    return {
        collisionFnCalls,
        state,
        msgPair
    };
}
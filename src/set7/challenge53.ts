import * as crypto from 'crypto';
import {CompressionFn, DigestDictionary} from './challenge52';
import {AES_128_BLOCK_LENGTH_BYTES, splitTextIntoBlocks} from '../set1/challenge7';
import {splitIntoBlocks} from '../set1/challenge6';

export type DifferingLengthCollisionPair = {
    shortMsgBlock: Buffer;
    longMsgBlock: Buffer;
    digest: Buffer;
}

export function findCollisionForMessagesOfDifferentLength(
    inputState: Buffer,
    dummyBlocks: ReadonlyArray<Buffer>,
    digestSizeInBytes: number,
    compressionFn: CompressionFn
): DifferingLengthCollisionPair {
    // compute hash of dummy blocks
    let curBlockDigest = inputState;
        for (let bIdx = 0; bIdx < dummyBlocks.length; bIdx++) {
        curBlockDigest = compressionFn(curBlockDigest, dummyBlocks[bIdx]);
    }
    let collisionPair: DifferingLengthCollisionPair | null = null;
    do {
        // generate 2^(n/2) different messages
        const msgs = Array(Math.pow(2, (digestSizeInBytes / 2) * 8));
        let msg: Buffer;
        for (let i = 0; i < msgs.length; i++) {
            msg = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
            msgs[i] = msg;
        }
        // compute their hashes & look for a collision
        const inputStateDigests: DigestDictionary = {};
        const intermediateStateDigests: DigestDictionary = {};
        let curInputStateDigestHex: string, curIntermediateStateDigestHex: string;
        for (let i = 0; i < msgs.length; i++) {
            curInputStateDigestHex = compressionFn(inputState, msgs[i]).toString('hex');
            curIntermediateStateDigestHex = compressionFn(curBlockDigest, msgs[i]).toString('hex');
            if (inputStateDigests[curIntermediateStateDigestHex]) {
                collisionPair = {
                    shortMsgBlock: Buffer.from(inputStateDigests[curIntermediateStateDigestHex], 'hex'),
                    longMsgBlock: Buffer.from(msgs[i], 'hex'),
                    digest: Buffer.from(curIntermediateStateDigestHex, 'hex')
                };
                break;
            } else if (intermediateStateDigests[curInputStateDigestHex]) {
                collisionPair = {
                    shortMsgBlock: Buffer.from(msgs[i], 'hex'),
                    longMsgBlock: Buffer.from(intermediateStateDigests[curInputStateDigestHex], 'hex'),
                    digest: Buffer.from(curInputStateDigestHex, 'hex')
                };
                break;
            }
            inputStateDigests[curInputStateDigestHex] = msgs[i].toString('hex');
            intermediateStateDigests[curIntermediateStateDigestHex] = msgs[i].toString('hex');
        }
    } while (!collisionPair);
    return collisionPair;
}

export type ExpandableMessageBlock = {
    shortMsg: Buffer;
    longMsg: Buffer;
    state: Buffer;
}

export function createExpandableMessage(
    k: number,
    initialState: Buffer,
    digestSizeInBytes: number,
    compressionFn: CompressionFn,
): Array<ExpandableMessageBlock> {
    const pairs: Array<ExpandableMessageBlock> = Array(k);
    // create dummy blocks
    const dummyBlock = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES, 0xFF);
    const dummyBlocksArr = Array(Math.pow(2, k-1));
    for (let i = 0; i < dummyBlocksArr.length; i++) dummyBlocksArr[i] = dummyBlock;
    let collisionPair: DifferingLengthCollisionPair, dummyBlocks: Buffer[], numOfDummyBlocks: number;
    let curBlockDigest = initialState;
    for (let i = k-1; i >= 0; i--) {
        numOfDummyBlocks = Math.pow(2, i);
        dummyBlocks = dummyBlocksArr.slice(0, numOfDummyBlocks);
        collisionPair = findCollisionForMessagesOfDifferentLength(
            curBlockDigest, dummyBlocks, digestSizeInBytes, compressionFn
        );
        pairs[k-1-i] = {
            longMsg: Buffer.concat([...dummyBlocks, collisionPair.longMsgBlock]),
            shortMsg: collisionPair.shortMsgBlock,
            state: curBlockDigest
        };
        curBlockDigest = collisionPair.digest;
    }
    return pairs;
}

export function expandMessageToLength(
    expandableMessageBlocks: ReadonlyArray<ExpandableMessageBlock>,
    desiredLengthInBlocks: number
): Buffer[] {
    const expanded: Array<Buffer> = Array(desiredLengthInBlocks);
    const diff = desiredLengthInBlocks - expandableMessageBlocks.length;
    let expandedIdx = 0;
    const base = expandableMessageBlocks.length - 1;
    for (let bIdx = 0; bIdx <= base; bIdx++) {
        if (diff & (1 << (base - bIdx))) {
            const blocks = splitTextIntoBlocks(expandableMessageBlocks[bIdx].longMsg, AES_128_BLOCK_LENGTH_BYTES);
            for (let lIdx = 0; lIdx < blocks.length; lIdx++) {
                expanded[expandedIdx++] = blocks[lIdx];
            }
        } else {
            expanded[expandedIdx++] = expandableMessageBlocks[bIdx].shortMsg;
        }
    }
    return expanded;
}

function findLinkingBlock(
    finalState: Buffer,
    computedDigestBlockMap: {[digest: string]: number},
    compressionFn: CompressionFn,
    digestSizeInBytes: number,
    numOfAttempts: number,
): { linkingBlock: Buffer; linkIdx: number } {
    let linkingBlock: Buffer | null = null, linkingDigest: Buffer, linkIdx = null;
    do {
        for (let i = 0; i < numOfAttempts; i++) {
            linkingBlock = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
            linkingDigest = compressionFn(finalState, linkingBlock);
            if (computedDigestBlockMap[linkingDigest.toString('hex')]) {
                // Note the index i it maps to.
                linkIdx = computedDigestBlockMap[linkingDigest.toString('hex')];
                break;
            }
        }
    } while (!linkIdx || !linkingBlock);
    return { linkingBlock, linkIdx };
}

function generateHashStatesMap(
    initialState: Buffer,
    msgBlocks: ReadonlyArray<Buffer>,
    compressionFn: CompressionFn,
    k: number
): {[digest: string]: number} {
    const digestBlockIdxMap: { [key: string]: number } = {};
    let digest = initialState;
    for (let bIdx = 0; bIdx < msgBlocks.length; bIdx++) {
        if (bIdx >= k + 1) {
            digestBlockIdxMap[digest.toString('hex')] = bIdx;
        }
        digest = compressionFn(digest, msgBlocks[bIdx]);
    }
    return digestBlockIdxMap;
}

export function findSecondPreimageForLongMessage(
    msg: Buffer,
    initialState: Buffer,
    digestSizeInBytes: number,
    compressionFn: CompressionFn,
): Buffer {
    const msgBlocks = splitIntoBlocks(msg, AES_128_BLOCK_LENGTH_BYTES);
    // 1. Generate an expandable message of length (k, k + 2^k - 1) using the strategy outlined above
    const k = Math.ceil(Math.log2(msgBlocks.length));
    const expandableMessageBlocks = createExpandableMessage(k, initialState, digestSizeInBytes, compressionFn);
    // 2. Hash M and generate a map of intermediate hash states to the block indices that they correspond to.
    const digestBlockIdxMap = generateHashStatesMap(initialState, msgBlocks, compressionFn, k);
    // 3. From your expandable message's final state, find a single-block "bridge" to intermediate state in your map.
    const finalState = compressionFn(
        expandableMessageBlocks[expandableMessageBlocks.length - 1].state,
        expandableMessageBlocks[expandableMessageBlocks.length - 1].shortMsg
    );
    const numOfAttempts = Math.pow(2, (digestSizeInBytes * 8) - k);
    const { linkingBlock, linkIdx } = findLinkingBlock(
        finalState, digestBlockIdxMap, compressionFn, digestSizeInBytes, numOfAttempts
    );
    // 4. Use your expandable message to generate a prefix of the right length such that len(prefix || bridge || M[i..]) = len(M).
    const expandedBlocks = expandMessageToLength(expandableMessageBlocks, linkIdx - 1);
    return Buffer.concat([...expandedBlocks, linkingBlock, ...msgBlocks.slice(linkIdx)]);
}
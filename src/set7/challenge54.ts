import * as crypto from 'crypto';
import {CompressionFn} from './challenge52';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {splitIntoBlocks} from '../set1/challenge6';

export type MsgDigestPair = { msg: Buffer; digest: Buffer };

// key: hex state, value: (message block, computed digest)
export type DiamondStructureLayer = Map<string, MsgDigestPair>;

export type DiamondStructure = {
    layers: Array<DiamondStructureLayer>;
};

/**
 * Generate map: K: digest, V: block
 * @param state state used when computing the digest
 * @param numOfCandidateBlocks number of blocks which are going to be generated
 * @param compressionFn compression function
 * @param prevCandidates previous blocks used
 */
function generateCandidateBlocksMap(
    state: Buffer,
    numOfCandidateBlocks: number,
    compressionFn: CompressionFn,
    prevCandidates?: ReadonlyArray<Buffer>
): Map<string, Buffer> {
    // digest -> block
    const dictionary: Map<string, Buffer> = new Map();
    const usedBlocks: Set<string> = prevCandidates ?
        new Set(prevCandidates.map(c => c.toString('hex'))) : new Set();
    let candidateBlock: Buffer, candidateDigest: Buffer;
    for (let k = 0; k < numOfCandidateBlocks; k++) {
        candidateBlock = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
        while (usedBlocks.has(candidateBlock.toString('hex'))) {
            candidateBlock = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
        }
        candidateDigest = compressionFn(state, candidateBlock);
        usedBlocks.add(candidateBlock.toString('hex'));
        dictionary.set(candidateDigest.toString('hex'), candidateBlock);
    }
    return dictionary;
}

/**
 * Randomly generate states
 * @param numOfStates number of states to be generated
 * @param digestSizeInBytes size of each generated state
 */
function generateStates(
    numOfStates: number,
    digestSizeInBytes: number
): Array<Buffer> {
    const statesSet: Set<string> = new Set();
    let randomState: Buffer;
    for (let j = 0; j < numOfStates; j++) {
        // randomly generate states
        randomState = crypto.randomBytes(digestSizeInBytes);
        while (statesSet.has(randomState.toString('hex'))) {
            randomState = crypto.randomBytes(digestSizeInBytes);
        }
        statesSet.add(randomState.toString('hex'));
    }
    return Array.from(statesSet).map(hexState => Buffer.from(hexState, 'hex'));
}

function generateCandidateBlocks(
    i: number,
    states: ReadonlyArray<Buffer>,
    compressionFn: CompressionFn,
    digestSizeInBytes: number,
): Map<string, Map<string, Buffer>> {
    const numOfCandidateBlocks = Math.pow(2, Math.ceil(((digestSizeInBytes  * 8) - i + 1) / 2));
    const stateToDigestMap = new Map<string, Map<string, Buffer>>();
    for (let j = 0; j < states.length; j++) {
        stateToDigestMap.set(states[j].toString('hex'),
            generateCandidateBlocksMap(states[j], numOfCandidateBlocks, compressionFn)
        );
    }
    return stateToDigestMap;
}

type DiamondStructureCollision = {
    state1: string;
    msgPair1: MsgDigestPair;
    state2: string;
    msgPair2: MsgDigestPair;
};

function findDiamondCollisionForState(
    curStateHex: string,
    stateToDigestMap: Map<string, Map<string, Buffer>>,
    states: ReadonlyArray<Buffer>,
    layer: DiamondStructureLayer,
    digests: Set<string>
): DiamondStructureCollision | undefined {
    const curStateDigestToMsgMap = stateToDigestMap.get(curStateHex) as Map<string, Buffer>;
    const curStateDigests = Array.from(curStateDigestToMsgMap.keys());
    let otherStateHex: string, otherStateDigests: string[], otherStateDigestToMsgMap: Map<string, Buffer>;
    let collision: DiamondStructureCollision | undefined;
    for (let otherStateIdx = 0; otherStateIdx < states.length; otherStateIdx++) {
        otherStateHex = states[otherStateIdx].toString('hex');
        if (curStateHex != otherStateHex && !layer.has(otherStateHex)) {
            otherStateDigestToMsgMap = stateToDigestMap.get(otherStateHex) as Map<string, Buffer>;
            otherStateDigests = Array.from(otherStateDigestToMsgMap.keys());
            const match = curStateDigests.find(digest =>
                !digests.has(digest) && otherStateDigests.includes(digest)
            );
            if (match) {
                const matchBuffer = Buffer.from(match, 'hex');
                collision = {
                    state1: curStateHex,
                    msgPair1: { msg: curStateDigestToMsgMap.get(match) as Buffer, digest: matchBuffer },
                    state2: otherStateHex,
                    msgPair2: { msg: otherStateDigestToMsgMap.get(match) as Buffer, digest: matchBuffer },
                }
                break;
            }
        }
    }
    return collision;
}

/**
 * Initialize i-th layer of diamond structure
 * @param i layer number
 * @param compressionFn compression function
 * @param digestSizeInBytes digest size in bytes
 * @param prevLayer previous layer of diamond structure
 */
export function initIthLayerOfDiamondStructure(
    i: number,
    compressionFn: CompressionFn,
    digestSizeInBytes: number,
    prevLayer?: DiamondStructureLayer,
): DiamondStructureLayer {
    const numOfStates = Math.pow(2, i);
    const layer: DiamondStructureLayer = new Map<string, MsgDigestPair>();
    const digests: Set<string> = new Set();
    let states: Buffer[];
    if (prevLayer) {
        // use previous layer
        const previousDigests = Array.from(prevLayer.values()).map((msgDigestPair) => msgDigestPair.digest);
        states = Array.from(new Set(previousDigests));
    } else {
        // "first" layer
        states = generateStates(numOfStates, digestSizeInBytes);
    }
    // generate candidate blocks for each state
    const stateToDigestMap = generateCandidateBlocks(i, states, compressionFn, digestSizeInBytes);
    let curStateHex: string, curStateDigestToMsgMap: Map<string, Buffer>, curCollision: DiamondStructureCollision | undefined;
    // find collision for each state
    for (let curStateIdx = 0; curStateIdx < states.length; curStateIdx++) {
        curStateHex = states[curStateIdx].toString('hex');
        while (!layer.has(curStateHex)) {
            curStateDigestToMsgMap = stateToDigestMap.get(curStateHex) as Map<string, Buffer>;
            curCollision = findDiamondCollisionForState(curStateHex, stateToDigestMap, states, layer, digests);
            if (curCollision) {
                layer.set(curCollision.state1, curCollision.msgPair1);
                layer.set(curCollision.state2, curCollision.msgPair2);
                digests.add(curCollision.msgPair1.digest.toString('hex'));
            } else {
                // if no collision could be found for current state, generate new candidate blocks
                const candidates = generateCandidateBlocksMap(
                    states[curStateIdx], curStateDigestToMsgMap.size,
                    compressionFn, Array.from(curStateDigestToMsgMap.values())
                );
                stateToDigestMap.set(curStateHex, candidates);
            }
        }
    }
    return layer;
}

/**
 * Initialize diamond structure
 * @param k k-parameter
 * @param compressionFn compression function
 * @param compressionFnDigestSize digest size of compression function in bytes
 */
export function initDiamondStructure(
    k: number,
    compressionFn: CompressionFn,
    compressionFnDigestSize: number,
): DiamondStructure {
    const layers = Array(k);
    let prevLayer: DiamondStructureLayer | null = null;
    for (let i = k; i > 0; i--) {
        layers[i - 1] = i == k ?
            initIthLayerOfDiamondStructure(i, compressionFn, compressionFnDigestSize) :
            initIthLayerOfDiamondStructure(i, compressionFn, compressionFnDigestSize, prevLayer as DiamondStructureLayer);
        prevLayer = layers[i - 1];
    }
    return {
        layers
    }
}

export function findLinkingBlock(
    msgDigest: Buffer,
    layer: DiamondStructureLayer,
    compressionFn: CompressionFn
): Buffer {
    let randomBlock: Buffer = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
    let randomDigestHex: string = compressionFn(msgDigest, randomBlock).toString('hex');
    while (!layer.has(randomDigestHex)) {
        randomBlock = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
        randomDigestHex = compressionFn(msgDigest, randomBlock).toString('hex');
    }
    return randomBlock;
}

export function constructChainOfBlocks(
    k: number,
    initialDigest: string,
    diamondStructure: DiamondStructure,
): Buffer[] {
    const blocks = Array(k);
    let curDigest = initialDigest, curLayer, curMsgPair;
    for (let curLayerIdx = k - 1; curLayerIdx >= 0; curLayerIdx--) {
        curLayer = diamondStructure.layers[curLayerIdx];
        curMsgPair = curLayer.get(curDigest) as MsgDigestPair;
        blocks[k - 1 - curLayerIdx] = curMsgPair.msg;
        curDigest = curMsgPair.digest.toString('hex');
    }
    return blocks;
}

export function getPredictionHashFromDiamondStructure(
    predictionLengthInBytes: number,
    finalLayer: DiamondStructureLayer,
    compressionFn: CompressionFn
): Buffer {
    const key = Array.from(finalLayer.keys())[0]
    const msgPair = finalLayer.get(key) as MsgDigestPair;
    const prefinalDigest = msgPair.digest;
    const paddingBlock = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES);
    paddingBlock[0] = 0x80; // 1 bit
    // length of the prediction document
    paddingBlock.writeUInt32BE(predictionLengthInBytes * 8, paddingBlock.length - 4);
    return compressionFn(prefinalDigest, paddingBlock);
}

export function generatePredictionFromDiamondStructure(
    initialState: Buffer,
    msg: Buffer,
    k: number,
    diamondStructure: DiamondStructure,
    compressionFn: CompressionFn
): Buffer {
    // compute hash of the prediction
    const msgBlocks = splitIntoBlocks(msg, AES_128_BLOCK_LENGTH_BYTES);
    let msgDigest = initialState;
    for (let i = 0; i < msgBlocks.length; i++) {
        msgDigest = compressionFn(msgDigest, msgBlocks[i]);
    }
    // find a linking message
    const layer = diamondStructure.layers[k - 1];
    const linkingBlock = findLinkingBlock(msgDigest, layer, compressionFn);
    // copy original msg
    const prediction = Buffer.alloc((msgBlocks.length + k + 1) * AES_128_BLOCK_LENGTH_BYTES);
    msg.copy(prediction, 0);
    // copy linking block
    linkingBlock.copy(prediction, msg.length);
    // copy matching blocks from the diamond structure
    const initialDigest = compressionFn(msgDigest, linkingBlock).toString('hex');
    const diamondBlocks = constructChainOfBlocks(k, initialDigest, diamondStructure);
    const suffix = Buffer.concat(diamondBlocks);
    suffix.copy(prediction, msg.length + linkingBlock.length);
    return prediction;
}
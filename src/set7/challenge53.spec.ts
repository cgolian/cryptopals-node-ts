import * as crypto from 'crypto';
import {
    CompressionFn,
    createCustomMDCompressionFunction, createCustomMDHashFunction, HashFn
} from './challenge52';
import {
    createExpandableMessage, expandMessageToLength,
    findCollisionForMessagesOfDifferentLength,
    findSecondPreimageForLongMessage
} from './challenge53';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {splitIntoBlocks} from '../set1/challenge6';

describe('Challenge 53', () => {
    describe('Find collision', () => {
        let digestSize: number;
        let compressionFn: CompressionFn;

        beforeEach(() => {
            digestSize = 2;
            compressionFn = createCustomMDCompressionFunction(digestSize);
        });

        it('should find collision for messages of 9 and 1 blocks', () => {
            const initialState = crypto.randomBytes(digestSize);
            const dummyBuffer = Buffer.alloc(8 * AES_128_BLOCK_LENGTH_BYTES, 0xFF);
            const dummyBlocks = splitIntoBlocks(dummyBuffer, AES_128_BLOCK_LENGTH_BYTES);

            const result = findCollisionForMessagesOfDifferentLength(initialState, dummyBlocks, digestSize, compressionFn); // TEST

            let digest = initialState;
            const longBlocks = [...dummyBlocks, ...splitIntoBlocks(result.longMsgBlock, AES_128_BLOCK_LENGTH_BYTES)];
            for (let bIdx = 0; bIdx < longBlocks.length; bIdx++) {
               digest = compressionFn(digest, longBlocks[bIdx]);
            }
            expect(digest).toEqual(compressionFn(initialState, result.shortMsgBlock));
        });
    });

    describe('Expandable message', () => {
        let digestSize: number;
        let compressionFn: CompressionFn;

        beforeEach(() => {
            digestSize = 2;
            compressionFn = createCustomMDCompressionFunction(digestSize);
        });

        it('should create an expandable message', () => {
            const initialState = crypto.randomBytes(digestSize);

            const expandableMsg = createExpandableMessage(10, initialState, digestSize, compressionFn); // TEST

            expect(expandableMsg.length).toEqual(10);
            expect(expandableMsg.every(block => {
                let digest = block.state;
                const blocks = splitIntoBlocks(block.longMsg, AES_128_BLOCK_LENGTH_BYTES);
                for (let bIdx = 0; bIdx < blocks.length; bIdx++) {
                    digest = compressionFn(digest, blocks[bIdx]);
                }
                return digest.equals(compressionFn(block.state, block.shortMsg));
            })).toEqual(true);
        });

        it('should expand message to desired length', () => {
            const initialState = crypto.randomBytes(digestSize);

            const expandableMsg = createExpandableMessage(4, initialState, digestSize, compressionFn);
            const result = expandMessageToLength(expandableMsg, 10); // TEST

            expect(result.length).toEqual(10);
            expect(result.every(msg => msg.length === AES_128_BLOCK_LENGTH_BYTES)).toEqual(true);
        });
    });

    describe('Message of 2^k blocks', () => {
        let digestSize: number;
        let compressionFn: CompressionFn;
        let hashFn: HashFn;
        let msg: Buffer;

        beforeEach(() => {
            digestSize = 2;
            compressionFn = createCustomMDCompressionFunction(digestSize);
            hashFn = createCustomMDHashFunction(compressionFn);
        });

        it('should find second preimage for k = 10', () => {
            const initialState = crypto.randomBytes(digestSize);
            const msgBlock = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES);
            msg = Buffer.alloc(1024 * AES_128_BLOCK_LENGTH_BYTES) // 2 ^ 10 = 1024
            for (let i = 0; i < 1024; i++) {
                msgBlock.writeUInt32BE(i);
                msgBlock.copy(msg,  i * AES_128_BLOCK_LENGTH_BYTES);
            }

            const preimage = findSecondPreimageForLongMessage(msg, initialState, digestSize, compressionFn); // TEST

            expect(preimage.length).toEqual(msg.length);
            expect(hashFn(initialState, msg)).toEqual(hashFn(initialState, preimage));
        });
    });
});
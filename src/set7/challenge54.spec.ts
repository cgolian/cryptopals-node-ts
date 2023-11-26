import {
   constructChainOfBlocks,
   DiamondStructure,
   findLinkingBlock, generatePredictionFromDiamondStructure, getPredictionHashFromDiamondStructure,
   initDiamondStructure,
   initIthLayerOfDiamondStructure
} from './challenge54';
import {CompressionFn, createCustomMDCompressionFunction, createCustomMDHashFunction, HashFn} from './challenge52';
import * as crypto from 'crypto';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';

describe('Challenge 54', () => {
   describe('Diamond structure', () => {
      let digestSizeBytes: number;
      let compressionFn: CompressionFn;

      beforeEach(() => {
         digestSizeBytes = 2;
         compressionFn = createCustomMDCompressionFunction(digestSizeBytes);
      });

      it('should generate "first" layer', () => {
         const i = 9;

         const result = initIthLayerOfDiamondStructure(i, compressionFn, digestSizeBytes); // TEST

         expect(result.size).toEqual(512); // 2^9
      });

      it('should generate "next" layer', () => {
         const i = 9;

         const firstLayer = initIthLayerOfDiamondStructure(i, compressionFn, digestSizeBytes);
         const result = initIthLayerOfDiamondStructure(i - 1, compressionFn, digestSizeBytes, firstLayer); // TEST

         expect(result.size).toEqual(256); // 2^(9 - 1)
      });

      it('should compute 2^(i-1) unique digests for layer', () => {
         const i = 5;

         const layer = initIthLayerOfDiamondStructure(i, compressionFn, digestSizeBytes); // TEST

         const uniqueDigests = new Set(Array.from(layer.values()).map(pair => pair.digest));
         expect(uniqueDigests.size).toEqual(16); // 2^(5 - 1)
      });

      it('should generate diamond structure', () => {
         const i = 5;

         const result = initDiamondStructure(i, compressionFn, digestSizeBytes); // TEST

         expect(result.layers.length).toEqual(i);
         expect(result.layers[0].size).toEqual(2);
         expect(result.layers[3].size).toEqual(16);
         expect(result.layers[4].size).toEqual(32);
      });
   });

   describe('Helper functions', () => {
      let k: number;
      let digestSizeBytes: number;
      let compressionFn: CompressionFn;
      let diamondStructure: DiamondStructure;

      beforeEach(() => {
         k = 5;
         digestSizeBytes = 2;
         compressionFn = createCustomMDCompressionFunction(digestSizeBytes);
         diamondStructure = initDiamondStructure(k, compressionFn, digestSizeBytes);
      });

      it('should find a linking block', () => {
         const msgDigest = crypto.randomBytes(digestSizeBytes);
         const layer = diamondStructure.layers[k - 1];

         const linkingBlock = findLinkingBlock(msgDigest, layer, compressionFn); // TEST

         const hexDigest = compressionFn(msgDigest, linkingBlock).toString('hex');
         expect(layer.has(hexDigest)).toEqual(true);
      });

      it('should construct a chain of blocks using the diamond structure', () => {
         const msgDigest = crypto.randomBytes(digestSizeBytes);
         const layer = diamondStructure.layers[k - 1];

         const linkingBlock = findLinkingBlock(msgDigest, layer, compressionFn);
         const initialDigest = compressionFn(msgDigest, linkingBlock).toString('hex');

         const result = constructChainOfBlocks(k, initialDigest, diamondStructure); // TEST

         expect(result.length).toEqual(k);
      });
   });

   describe('Herding attack', () => {
      let k: number;
      let digestSizeBytes: number;
      let compressionFn: CompressionFn;
      let hashFn: HashFn;
      let diamondStructure: DiamondStructure;

      beforeEach(() => {
         digestSizeBytes = 2;
         k = 4;
         compressionFn = createCustomMDCompressionFunction(digestSizeBytes);
         hashFn = createCustomMDHashFunction(compressionFn);
         diamondStructure = initDiamondStructure(k, compressionFn, digestSizeBytes);
      });

      it('should generate "correct" prediction', () => {
         const initialState = crypto.randomBytes(digestSizeBytes);
         const msgLen = 2 * AES_128_BLOCK_LENGTH_BYTES;
         const predictionLengthInBytes = msgLen + (k + 1) * AES_128_BLOCK_LENGTH_BYTES;

         // hash would be the prediction that would be published
         const predictionHash = getPredictionHashFromDiamondStructure(
             predictionLengthInBytes, diamondStructure.layers[0], compressionFn
         );

         // after the event would take place document would be created to match the prediction
         const msg = Buffer.from(' this  would  be  my  prediction');
         const prediction = generatePredictionFromDiamondStructure(
             initialState, msg, k, diamondStructure, compressionFn
         ); // TEST

         expect(prediction.length).toEqual(predictionLengthInBytes);
         expect(hashFn(initialState, prediction)).toEqual(predictionHash);
      });
   });
});
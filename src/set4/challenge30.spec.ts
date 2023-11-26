import {
    computeMACwMD4,
    forgeSecretPrefixMACwMD4,
    initMD4SecretPrefixOracle,
    verifyMACwMD4
} from './challenge30';
// eslint-disable-next-line @typescript-eslint/camelcase
import {hex_md4, hex_md4_hex_input} from './md4';
import {
    padMessageMD, restoreHashFunctionState,
    SecretPrefixOracle
} from './challenge29';

describe('Challenge 30', () => {
   describe('MD4 MAC', () => {
       let msg: Buffer;
       let key: Buffer;

       beforeEach(() => {
           key = Buffer.from('secretkey');
           msg = Buffer.from('myinput');
       });

       it('should compute MD4 MAC', () => {
           const result = computeMACwMD4(msg, key); // TEST

           expect(result).toEqual(Buffer.from('d6949aa709705b7463abca67f27b8fe3', 'hex'));
       });

       it('should verify MD4 MAC', () => {
           const mac = computeMACwMD4(msg, key);

           expect(verifyMACwMD4(msg, mac, key)).toEqual(true); // TEST
       });
   });

   describe('helper functions', () => {
       let baseInput: Buffer;
       let baseHash: Buffer;
       let extraInput: Buffer;

       beforeEach(() => {
           baseInput = Buffer.from('randominput');
           baseHash = Buffer.from(hex_md4(baseInput.toString()), 'hex');
           extraInput = Buffer.from('extra');
       });

       it('should compute same hash for hex and regular input', () => {
           const regularInputHash = hex_md4(baseInput.toString());
           const hexInputHash = hex_md4_hex_input(baseInput.toString('hex')); // TEST

           expect(regularInputHash).toEqual(hexInputHash);
       });

       it('should restore state of MD4', () => {
           const state = [498427334,-243164335,132735744,973530193];

           expect(restoreHashFunctionState(baseHash, 'md4')).toEqual(state);
       });

       it('should compute hash of "additional" input with previous state', () => {
           const prevState = restoreHashFunctionState(baseHash, 'md4');
           const paddedInput = padMessageMD(baseInput, 512, 'LE');

           const concatHex = Buffer.concat([paddedInput, extraInput]).toString('hex');
           const concatLenBits = concatHex.length * 4;
           const concatHash = hex_md4_hex_input(concatHex);
           const extraHash = hex_md4_hex_input(extraInput.toString('hex'), prevState, concatLenBits);

           expect(concatHash).toEqual(extraHash);
       });
   });

    describe('secret prefix MAC forgery', () => {
        let secretKey: Buffer;
        let msg: Buffer;
        let mac: Buffer;
        let oracle: SecretPrefixOracle;

        beforeEach(() => {
            secretKey = Buffer.from('supersecret');
            oracle = initMD4SecretPrefixOracle(secretKey);
            msg = Buffer.from('comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon');
            mac = oracle.computeMAC(msg);
        });

        it('should forge MAC', () => {
            const additionalInput = Buffer.from(';admin=true');

            const result = forgeSecretPrefixMACwMD4(msg, mac, additionalInput, oracle); // TEST

            expect(result.keyLength).toEqual(secretKey.length);
            expect(oracle.verifyMAC(result.input, result.mac)).toEqual(true);
        });
    });
});
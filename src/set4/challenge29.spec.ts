import {forgeSecretPrefixMACwSHA1, initSHA1SecretPrefixOracle, padMessageMD, SecretPrefixOracle} from './challenge29';

describe('Challenge 29', () => {
    describe('MD padding', () => {
        const msg = Buffer.from([0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101]);
        let expected: Buffer;

        beforeEach(() => {
            expected = Buffer.alloc(64, 0x0);
            // original msg
            expected[0] = 0x61;
            expected[1] = 0x62;
            expected[2] = 0x63;
            expected[3] = 0x64;
            expected[4] = 0x65;
            // 1 bit
            expected[5] = 0x80;
            // msg length in bits - 5 x 8 = 40 bits = 0x28 in hex
            expected[expected.length - 1] = 0x28;
        });

        it('should pad message', () => {
            const padded = padMessageMD(msg, 512, 'BE'); // TEST

            expect(padded).toEqual(expected);
        });
    });

    describe('secret prefix MAC forgery', () => {
        let secretKey: Buffer;
        let msg: Buffer;
        let mac: Buffer;
        let oracle: SecretPrefixOracle;

        beforeEach(() => {
            secretKey = Buffer.from('supersecret');
            oracle = initSHA1SecretPrefixOracle(secretKey);
            msg = Buffer.from('comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon');
            mac = oracle.computeMAC(msg);
        });

        it('should forge MAC', () => {
            const additionalInput = Buffer.from(';admin=true');

            const result = forgeSecretPrefixMACwSHA1(msg, mac, additionalInput, oracle); // TEST

            expect(result.keyLength).toEqual(secretKey.length);
            expect(oracle.verifyMAC(result.input, result.mac)).toEqual(true);
        });
    });
});
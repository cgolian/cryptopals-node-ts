import {
    consistentKeyRandomPrefixEncryptionOracle, decryptConsistentKeyRandomPrefixEncryptionOracle,
    initOracleWithoutRandomPrefix,
    isolateRandomBytes
} from './challenge14';
import {
    consistentKeyEncryptionOracle,
    ConsistentKeyEncryptionOracle
} from './challenge12';

jest.mock('./challenge11', () => ({
    AESEncryptionOracle: class {
        static generateRandomKey(): Buffer {
            return Buffer.from([0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x1, 0x1, 0x2, 0x2, 0x2, 0x2, 0x3, 0x3, 0x3, 0x3]);
        }
    }
}));


describe('Challenge 14', () => {
    describe('Helper functions', () => {
        let mockedEncryptionOracle: ConsistentKeyEncryptionOracle;
        const randomPrefix = Buffer.from('randomprefix');
        const targetBytes = Buffer.from('targetbytes');

        beforeEach(() => {
            mockedEncryptionOracle = (plaintext: Buffer): Buffer =>
                Buffer.concat([randomPrefix, plaintext, targetBytes]);
        });

        describe('isolateRandomBytes', () => {
            it('should isolate random bytes', () => {
                expect(isolateRandomBytes(mockedEncryptionOracle)).toEqual(Buffer.from([0x0, 0x0, 0x0, 0x0])); // TEST
            });
        });

        describe('initOracleWithoutRandomPrefix', () => {
            let encryptionOracle: ConsistentKeyEncryptionOracle;
            let randomPrefixEncryptionOracle: ConsistentKeyEncryptionOracle;

            beforeEach(() => {
                encryptionOracle = consistentKeyEncryptionOracle();
                randomPrefixEncryptionOracle = consistentKeyRandomPrefixEncryptionOracle();
            });

            it('Should convert random prefix oracle to a regular one', () => {
                const isolatingInput = isolateRandomBytes(randomPrefixEncryptionOracle) as Buffer;
                const input = Buffer.from('aaa');
                const expectedResult = encryptionOracle(input);

                const oracle = initOracleWithoutRandomPrefix(randomPrefixEncryptionOracle, isolatingInput); // TEST
                const result = oracle(input);

                expect(expectedResult.length).toEqual(result.length);
                expect(expectedResult).toEqual(result);
            });
        });
    });

    describe('decryptConsistentKeyRandomPrefixEncryptionOracle', () => {
        let encryptionOracle: ConsistentKeyEncryptionOracle;

        beforeEach(() => {
           encryptionOracle = consistentKeyRandomPrefixEncryptionOracle();
        });

        xit('should decrypt target bytes', () => {
            const result = decryptConsistentKeyRandomPrefixEncryptionOracle(encryptionOracle); // TEST

            console.log(result);
        });
    });
});
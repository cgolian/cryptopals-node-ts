import {createEncryptionFunctionAndPaddingOraclePair, paddingOracleDecryptCBCCiphertext} from './challenge17';

describe('Challenge 17', () => {
    describe('Helper functions', () => {
        describe('cbcPaddingOracle', () => {
            let cbcEncryptionOracle: () => { ciphertext: Buffer; iv: Buffer };
            let cbcPaddingOracle: (ciphertext: Buffer) => boolean;

            beforeEach(() => {
                const { encryptCBC, paddingOracle } = createEncryptionFunctionAndPaddingOraclePair();
                cbcEncryptionOracle = encryptCBC;
                cbcPaddingOracle = paddingOracle;
            });

            it('should validate padding of a randomly encrypted string', () => {
                const { ciphertext } = cbcEncryptionOracle();
                expect(cbcPaddingOracle(ciphertext)).toEqual(true);
            });
        });
    });

    xdescribe('CBC ciphertext decryption', () => {
        let cbcEncryptionOracle: () => { ciphertext: Buffer; iv: Buffer };
        let cbcPaddingOracle: (ciphertext: Buffer) => boolean;

        beforeEach(() => {
            const { encryptCBC, paddingOracle } = createEncryptionFunctionAndPaddingOraclePair();
            cbcEncryptionOracle = encryptCBC;
            cbcPaddingOracle = paddingOracle;
        });

        it('should decrypt CBC ciphertext using padding oracle', () => {
            const { ciphertext, iv } = cbcEncryptionOracle();

            console.log(paddingOracleDecryptCBCCiphertext(
                ciphertext,
                iv,
                cbcPaddingOracle
            ).toString());
        });
    });
});
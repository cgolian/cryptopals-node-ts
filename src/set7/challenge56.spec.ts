import {initRC4EncryptionOracle, RC4EncryptionOracle} from "./challenge56";

describe('Challenge 56', () => {
   describe('RC4 encryption oracle', () => {
        let encryptionOracle: RC4EncryptionOracle;

        beforeEach(() => {
            encryptionOracle = initRC4EncryptionOracle();
        });

        it('should encrypt plaintext concatenated with cookie using RC4', () => {
            const plaintext = Buffer.from('hello');

            const result = encryptionOracle.encryptWithRandomKey(plaintext); // TEST

            expect(result.length).toBeGreaterThanOrEqual(plaintext.length);
       });
    });
});
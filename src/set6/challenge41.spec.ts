import {
    decryptCiphertextUsingRSAUnpaddedMessageRecoveryOracle,
    initRSAUnpaddedMessageRecoveryOracle,
    RSAUnpaddedMessageRecoveryOracle
} from "./challenge41";

describe('Challenge 41', () => {
    let messageRecoveryOracle: RSAUnpaddedMessageRecoveryOracle;

    beforeAll(() => {
        messageRecoveryOracle = initRSAUnpaddedMessageRecoveryOracle();
    });

    describe('unpadded message recovery oracle', () => {
        it('should decrypt message', () => {
            const plaintext = Buffer.from('message');

            const ciphertext = messageRecoveryOracle.encrypt(plaintext);

            const result = messageRecoveryOracle.decrypt(ciphertext); // TEST
            expect(plaintext).toEqual(result);
        });

        it('should throw when trying to a decrypt the same ciphertext for the second time', () => {
            const plaintext = Buffer.from('second message');

            const ciphertext = messageRecoveryOracle.encrypt(plaintext);

            messageRecoveryOracle.decrypt(ciphertext);
            expect(() => messageRecoveryOracle.decrypt(ciphertext)).toThrow(Error); // TEST
        });
    });

    describe('decrypt ciphertext using unpadded message recovery oracle', () => {
        it('should decrypt ciphertext', () => {
            const plaintext = Buffer.from('another message');
            const ciphertext = messageRecoveryOracle.encrypt(plaintext);

            const result = decryptCiphertextUsingRSAUnpaddedMessageRecoveryOracle(ciphertext, messageRecoveryOracle); // TEST

            expect(result).toEqual(plaintext);
        });
    });
});
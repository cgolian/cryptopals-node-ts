import {ciphertexts, decryptCtrCiphertextsEncryptedWithSameNonce} from './challenge20';

describe('Challenge 20', () => {
    xit('should decrypt ciphertexts', () => {
        const result = decryptCtrCiphertextsEncryptedWithSameNonce(ciphertexts);

        result.forEach((plaintext) => console.log(plaintext.toString()));
        expect(result.length).not.toEqual(0);
    });
});
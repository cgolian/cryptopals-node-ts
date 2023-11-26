import {AESEncryptionOracle} from './challenge11';
import {isECBEncrypted} from '../set1/challenge8';

describe('Challenge 11', () => {
    describe('Encryption oracle', () => {
       const plaintext = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567' +
            '89abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd' +
            'ef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123' +
            '456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789' +
            'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' +
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345' +
            '6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');

       let encryptionOracle: AESEncryptionOracle;

       beforeEach(() => {
            encryptionOracle = new AESEncryptionOracle();
       });

       it('should detect ECB encrypted ciphertext', () => {
           encryptionOracle.testEcbFlag = true;

           const ciphertext = encryptionOracle.encryptWithRandomKey(plaintext); // TEST

           const { result } = isECBEncrypted(ciphertext.toString());
           expect(result).toEqual(true);
       });

       it('should detect CBC encrypted ciphertext', () => {
           encryptionOracle.testEcbFlag = false;

           const ciphertext = encryptionOracle.encryptWithRandomKey(plaintext); // TEST

           const { result } = isECBEncrypted(ciphertext.toString());
           expect(result).toEqual(false);
       });
    });
});
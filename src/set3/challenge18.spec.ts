import {aes128CtrDecrypt, aes128CtrEncrypt} from './challenge18';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';

describe('Challenge 18', () => {
    let plaintext: Buffer;
    let ciphertext: Buffer;
    let key: Buffer;
    let nonce: Buffer;

    beforeEach(() => {
        plaintext = Buffer.from('Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ');
        ciphertext = Buffer.from('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==', 'base64');
        key = Buffer.from('YELLOW SUBMARINE');
        nonce = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES).fill(0x0);
    });


    it('should encrypt plaintext using CTR mode', () => {
        const result = aes128CtrEncrypt(plaintext, key, nonce); // TEST

        expect(result).toEqual(ciphertext);
    });

    it('should decrypt ciphertext using CTR mode', () => {
        const result = aes128CtrDecrypt(ciphertext, key, nonce); // TEST

        expect(result).toEqual(plaintext);
    });
});
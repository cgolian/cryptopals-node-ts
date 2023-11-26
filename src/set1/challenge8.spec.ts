import * as fs from 'fs';
import {isECBEncrypted} from './challenge8';

describe('Challenge 8', () => {
   it('Should find ECB encrypted ciphertext', () => {
       const fileContents = fs.readFileSync('./src/set1/8.txt', 'utf8');
       let ecbEncryptedCiphertextExists = false;
       for (const ciphertext of fileContents.split('\n')) {
           const result = isECBEncrypted(ciphertext);
           if (result.result) {
               ecbEncryptedCiphertextExists = true;
           }
       }
       expect(ecbEncryptedCiphertextExists).toEqual(true);
   });
});
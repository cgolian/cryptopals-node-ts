import * as fs from 'fs';
import {detectSingleByteXOREncryptedString} from './challenge4';

describe('Challenge 4', function () {
    xdescribe('Single byte XOR encryption detection', () => {
       let ciphertexts: string[];

       beforeAll(() => {
         const contents = fs.readFileSync('./src/set1/4.txt', 'utf8');
         ciphertexts = contents.split('\n')
       });

       it('Should find string encrypted with single byte XOR', () => {
           const expected = 'Now that the party is jumping\n';

           const result = detectSingleByteXOREncryptedString(ciphertexts); // TEST

           expect(result.decryptionInfo.plaintext.toString()).toEqual(expected);
       });
    });
});
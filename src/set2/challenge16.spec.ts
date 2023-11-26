import {CbcEncryptingFn, cbcFlipBits, CbcValidationFn, encryptData, isAdmin} from './challenge16';

describe('Challenge 16', () => {
    describe('CBC flip bits attack', () => {
       let encryptionFn: CbcEncryptingFn;
       let validationFn: CbcValidationFn;

       beforeEach(() => {
           encryptionFn = encryptData;
           validationFn = isAdmin;
       });

       it('should validate modified ciphertext', () => {
           const result = cbcFlipBits(encryptionFn, validationFn); // TEST

           expect(result).toBeDefined();
       });
    });
});
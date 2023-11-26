import {createCtrEncryptionOracle, CtrEncryptionOracle, plaintexts} from './challenge19';

describe('Challenge 19', () => {
    describe('CTR encryption oracle', () => {
       let ctrEncryptionOracle: CtrEncryptionOracle;

       beforeEach(() => {
           ctrEncryptionOracle = createCtrEncryptionOracle(plaintexts);
       });

       it('should encrypt plaintexts passed in as argument', () => {
           const result = ctrEncryptionOracle.encryptCiphertextsWithFixedNonceAndRandomKey(); // TEST

           expect(result.length).toEqual(plaintexts.length);
       });
    });
});
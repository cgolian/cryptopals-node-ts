import {XORHexStrings} from './challenge2';

describe('Challenge 2', () => {
    describe('XOR hex strings', () => {
       it('Should not XOR non-hex inputs', () => {
           const hex1 = 'tturigjklfdsgjklsdfjglksjdfgkljsdfgl';
           const hex2 = '686974207468652062756c6c277320657965';

           expect(() => XORHexStrings(hex1, hex2)).toThrow(Error); // TEST
       });

       it('Should not XOR hex inputs of different length', () => {
           const hex1 = '1c0111001f010100061a024b53535009';
           const hex2 = '686974207468652062756c6c277320657965';

           expect(() => XORHexStrings(hex1, hex2)).toThrow(Error); // TEST
       });

       it('Should XOR two hex strings', () => {
          const hex1 = '1c0111001f010100061a024b53535009181c';
          const hex2 = '686974207468652062756c6c277320657965';
          const expected = '746865206b696420646f6e277420706c6179';

          const result = XORHexStrings(hex1, hex2); // TEST

          expect(result).toEqual(expected);
       });
    });
});
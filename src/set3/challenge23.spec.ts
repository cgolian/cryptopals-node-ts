import {copyMT19937Generator, untemper} from './challenge23';
import {mt19937rng, SeededRng} from './challenge21';

describe('Challenge 23', () => {
   describe(`'untemper' function`, () => {
       it.each`
          before | after
          ${ 1440116776 } | ${2512043400},
          ${ -1646059829} | ${1857350917},
          ${ -2012270259} | ${2802994671},
          ${ -1412029067} | ${2909742186},
          ${ -511692019}  | ${1851268125},
          ${ 472734947}   | ${1736885417},
          ${ -106482510}  | ${1689918330},
          ${ -427173495}  | ${1121011718},
          ${ 1342746158}  | ${482524299},
          ${ -1301996427} | ${572070480},
       `(
           'given rng $before recovers the value before tempering $after',
           ({ before, after }) => {
               expect(untemper(after)).toEqual(before);
           }
       );
   });

   describe('copy generator', () => {
       let originalRng: SeededRng;
       let copiedRng: SeededRng;

       beforeEach(() => {
           originalRng = mt19937rng(1047, 32);
       });

       it(`should copy generator based on its outputs`, () => {
           copiedRng = copyMT19937Generator(originalRng); // TEST

           for (let i = 1; i < 100; i++) {
               expect(originalRng()).toEqual(copiedRng());
           }
       });
   });
});
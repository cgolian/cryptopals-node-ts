import {
    a1Constraints,
    a2Constraints,
    a3Constraints,
    a4Constraints, a5Constraints,
    applyConstraintsToWord, applyDifferential,
    b1Constraints,
    b2Constraints,
    b3Constraints,
    b4Constraints,
    c1Constraints,
    c2Constraints,
    c3Constraints,
    c4Constraints,
    d1Constraints,
    d2Constraints,
    d3Constraints,
    d4Constraints,
    md4FirstRoundBitShiftConstants,
    md4InitialState, md4SecondRoundBitShiftConstants,
    modifyMessageToMeetFirstRoundConstraints,
    modifyMessageToMeetSecondRoundConstraints,
    rrot,
    verifyConstraints
} from './challenge55';
// eslint-disable-next-line @typescript-eslint/camelcase
import {binl2hex, core_md4, hex_md4_hex_input, md4_ff, md4_gg, safe_add} from '../set4/md4';

describe('Challenge 55', () => {
   let a: number;
   let b: number;
   let c: number;
   let d: number;
   let originalMsg: number[];

   beforeEach(() => {
       a = md4InitialState[0];
       b = md4InitialState[1];
       c = md4InitialState[2];
       d = md4InitialState[3];

       originalMsg = [
           0x4f682074, 0x68652073, 0x6861726b, 0x20686173,
           0x20707265, 0x74747920, 0x74656574, 0x682c2044,
           0x6561720a, 0x416e6420, 0x68652073, 0x686f7773,
           0x20746865, 0x6d207065, 0x61726c79, 0x61726c80
       ];
   });

   describe('First round constraints', () => {
       let a1: number;

       beforeEach(() => {
          a1 = md4_ff(a, b, c, d, originalMsg[0], md4FirstRoundBitShiftConstants[0] );
       });

       it('should apply constraints to d1', () => {
           const dConstraints = Array(32).fill(null);
           dConstraints[6] = '1';
           dConstraints[7] = 'a';
           dConstraints[10] = 'a';

           let d1 = md4_ff(d, a1, b, c, originalMsg[1], md4FirstRoundBitShiftConstants[1]);
           d1 = applyConstraintsToWord({ word: d1, constraints: dConstraints }, {
               a: a1, b: b, c: c, d: d
           }); // TEST

           const modifiedWord = rrot(d1, md4FirstRoundBitShiftConstants[1]) - safe_add(d, ((a1 & b) | ((~a1) & c)));
           const computedD1 = md4_ff(d, a1, b, c, modifiedWord, md4FirstRoundBitShiftConstants[1]);

           expect(computedD1).toEqual(d1);
       })

       it('should verify constraints applied to d1', () => {
           const dConstraints = Array(32).fill(null);
           dConstraints[6] = '1';
           dConstraints[7] = 'a';
           dConstraints[10] = 'a';

           const origD1 = md4_ff(d, a1, b, c, originalMsg[1], md4FirstRoundBitShiftConstants[1]);
           const modifiedD1 = applyConstraintsToWord({ word: origD1, constraints: dConstraints }, {
               a: a1, b: b, c: c, d: origD1
           });

           const result = verifyConstraints(
               { word: modifiedD1, constraints: dConstraints }, {a: a1, b: b, c: c, d: modifiedD1}
           ); // TEST

           expect(result).toEqual(true);
       });

       it('should verify first round constraints applied to message', () => {
           const { words } = modifyMessageToMeetFirstRoundConstraints(originalMsg, [
               { a: a1Constraints, b: b1Constraints, c: c1Constraints, d: d1Constraints },
               { a: a2Constraints, b: b2Constraints, c: c2Constraints, d: d2Constraints },
               { a: a3Constraints, b: b3Constraints, c: c3Constraints, d: d3Constraints },
               { a: a4Constraints, b: b4Constraints, c: c4Constraints, d: d4Constraints },
           ]); // TEST

           // a1, b1, c1 and d1
           a = md4_ff(a, b, c, d, words[0], md4FirstRoundBitShiftConstants[0] );
           expect(verifyConstraints(
               { word: a, constraints: a1Constraints }, { a, b, c, d })
           ).toEqual(true);

           d = md4_ff(d, a, b, c, words[1], md4FirstRoundBitShiftConstants[1] );
           expect(verifyConstraints(
               { word: d, constraints: d1Constraints }, { a, b, c, d })
           ).toEqual(true);

           c = md4_ff(c, d, a, b, words[2], md4FirstRoundBitShiftConstants[2]);
           expect(verifyConstraints(
               { word: c, constraints: c1Constraints }, { a, b, c, d })
           ).toEqual(true);

           b = md4_ff(b, c, d, a, words[3], md4FirstRoundBitShiftConstants[3]);
           expect(verifyConstraints(
               { word: b, constraints: b1Constraints }, { a, b, c, d })
           ).toEqual(true);
           // a2, b2, c2 and d2
           a = md4_ff(a, b, c, d, words[4], md4FirstRoundBitShiftConstants[0] );
           expect(verifyConstraints(
               { word: a, constraints: a2Constraints }, { a, b, c, d })
           ).toEqual(true);

           d = md4_ff(d, a, b, c, words[5], md4FirstRoundBitShiftConstants[1] );
           expect(verifyConstraints(
               { word: d, constraints: d2Constraints }, { a, b, c, d })
           ).toEqual(true);

           c = md4_ff(c, d, a, b, words[6], md4FirstRoundBitShiftConstants[2]);
           expect(verifyConstraints(
               { word: c, constraints: c2Constraints }, { a, b, c, d })
           ).toEqual(true);

           b = md4_ff(b, c, d, a, words[7], md4FirstRoundBitShiftConstants[3]);
           expect(verifyConstraints(
               { word: b, constraints: b2Constraints }, { a, b, c, d })
           ).toEqual(true);
           // a3, b3, c3 and d3
           a = md4_ff(a, b, c, d, words[8], md4FirstRoundBitShiftConstants[0] );
           expect(verifyConstraints(
               { word: a, constraints: a3Constraints }, { a, b, c, d })
           ).toEqual(true);

           d = md4_ff(d, a, b, c, words[9], md4FirstRoundBitShiftConstants[1] );
           expect(verifyConstraints(
               { word: d, constraints: d3Constraints }, { a, b, c, d })
           ).toEqual(true);

           c = md4_ff(c, d, a, b, words[10], md4FirstRoundBitShiftConstants[2]);
           expect(verifyConstraints(
               { word: c, constraints: c3Constraints }, { a, b, c, d })
           ).toEqual(true);

           b = md4_ff(b, c, d, a, words[11], md4FirstRoundBitShiftConstants[3]);
           expect(verifyConstraints(
               { word: b, constraints: b3Constraints }, { a, b, c, d })
           ).toEqual(true);
           // a4, b4, c4 and d4
           a = md4_ff(a, b, c, d, words[12], md4FirstRoundBitShiftConstants[0] );
           expect(verifyConstraints(
               { word: a, constraints: a4Constraints }, { a, b, c, d })
           ).toEqual(true);

           d = md4_ff(d, a, b, c, words[13], md4FirstRoundBitShiftConstants[1]);
           expect(verifyConstraints(
               { word: d, constraints: d4Constraints }, { a, b, c, d })
           ).toEqual(true);

           c = md4_ff(c, d, a, b, words[14], md4FirstRoundBitShiftConstants[2]);
           expect(verifyConstraints(
               { word: c, constraints: c4Constraints }, { a, b, c, d })
           ).toEqual(true);

           b = md4_ff(b, c, d, a, words[15], md4FirstRoundBitShiftConstants[3]);
           expect(verifyConstraints(
               { word: b, constraints: b4Constraints }, { a, b, c, d })
           ).toEqual(true);
       });

       it('should verify computed states', () => {
          const { words, states } = modifyMessageToMeetFirstRoundConstraints(originalMsg, [
              { a: a1Constraints, b: b1Constraints, c: c1Constraints, d: d1Constraints },
              { a: a2Constraints, b: b2Constraints, c: c2Constraints, d: d2Constraints },
              { a: a3Constraints, b: b3Constraints, c: c3Constraints, d: d3Constraints },
              { a: a4Constraints, b: b4Constraints, c: c4Constraints, d: d4Constraints },
          ]); // TEST

          expect(states.length).toEqual(5);

           a = md4_ff(a, b, c, d, words[0], 3 );
           d = md4_ff(d, a, b, c, words[1], 7 );
           c = md4_ff(c, d, a, b, words[2], 11);
           b = md4_ff(b, c, d, a, words[3], 19);

           a = md4_ff(a, b, c, d, words[4], 3 );
           d = md4_ff(d, a, b, c, words[5], 7 );
           c = md4_ff(c, d, a, b, words[6], 11);
           b = md4_ff(b, c, d, a, words[7], 19);

           a = md4_ff(a, b, c, d, words[8], 3 );
           d = md4_ff(d, a, b, c, words[9], 7 );
           c = md4_ff(c, d, a, b, words[10], 11);
           b = md4_ff(b, c, d, a, words[11], 19);

           a = md4_ff(a, b, c, d, words[12], 3 );
           d = md4_ff(d, a, b, c, words[13], 7 );
           c = md4_ff(c, d, a, b, words[14], 11);
           b = md4_ff(b, c, d, a, words[15], 19);

          expect(states[4]).toEqual({ a, b, c, d });
       });
   });

   describe('Second round constraints', () => {
       let msg: number[];
       let msgStates: { a: number; b: number; c: number; d: number}[];

       beforeEach(() => {
           const { words, states } = modifyMessageToMeetFirstRoundConstraints(originalMsg, [
               { a: a1Constraints, b: b1Constraints, c: c1Constraints, d: d1Constraints },
               { a: a2Constraints, b: b2Constraints, c: c2Constraints, d: d2Constraints },
               { a: a3Constraints, b: b3Constraints, c: c3Constraints, d: d3Constraints },
               { a: a4Constraints, b: b4Constraints, c: c4Constraints, d: d4Constraints },
           ]);

           msg = words;
           msgStates = states;
       });

       it('should verify second round constraints applied to message', () => {
           const modifiedMsg = modifyMessageToMeetSecondRoundConstraints(msg, msgStates); // TEST

           const a5 = md4_gg(
               msgStates[4].a, msgStates[4].b, msgStates[4].c, msgStates[4].d,
               modifiedMsg[0],
               md4SecondRoundBitShiftConstants[0]);
           expect(verifyConstraints(
               { word: a5, constraints: a5Constraints },
               { a: msgStates[4].a, b: msgStates[4].b, c: msgStates[4].c, d: msgStates[4].d})
           ).toEqual(true);
      });

      describe('First round constraints still hold', () => {
          let modifiedMsg: number[];
          let a1: number;

          beforeEach(() => {
              modifiedMsg = modifyMessageToMeetSecondRoundConstraints(originalMsg, msgStates);
              a1 = md4_ff(
                  msgStates[0].a, msgStates[0].b, msgStates[0].c, msgStates[0].d,
                  modifiedMsg[0],
                  md4FirstRoundBitShiftConstants[0]
              );
          });

          it('should verify that first round constraints still hold for a1', () => {
              expect(verifyConstraints(
                  { word: a1, constraints: a1Constraints },
                  { a1, b: msgStates[0].b, c: msgStates[0].c, d: msgStates[0].d })
              ).toEqual(true);
          });

          it('should verify that first round constraints still hold for d1', () => {
              const d1 = md4_ff(
                  msgStates[0].d, a1, msgStates[0].b, msgStates[0].c,
                  modifiedMsg[1],
                  md4FirstRoundBitShiftConstants[1]
              ); // TEST

              expect(d1).toEqual(msgStates[1].d);
              expect(verifyConstraints(
                  { word: d1, constraints: d1Constraints },
                  { a: a1, b: msgStates[0].b, c: msgStates[0].c, d: msgStates[0].d })
              ).toEqual(true);
          });

          it('should verify that first round constraints still hold for c1', () => {
              const c1 = md4_ff(
                  msgStates[0].c, msgStates[1].d, a1, msgStates[0].b,
                  modifiedMsg[2],
                  md4FirstRoundBitShiftConstants[2]
              ); // TEST

              expect(c1).toEqual(msgStates[1].c);
              expect(verifyConstraints(
                  { word: c1, constraints: c1Constraints },
                  { a: msgStates[0].a, b: msgStates[0].b, c: c1, d: msgStates[1].d })
              ).toEqual(true);
          });

          it('should verify that first round constraints still hold for b1', () => {
              const b1 = md4_ff(
                  msgStates[0].b, msgStates[1].c, msgStates[1].d, a1,
                  modifiedMsg[3],
                  md4FirstRoundBitShiftConstants[3]
              ); // TEST

              expect(b1).toEqual(msgStates[1].b);
              expect(verifyConstraints(
                  { word: b1, constraints: b1Constraints },
                  { a: a1, b: b1, c: msgStates[1].c, d: msgStates[1].d })
              ).toEqual(true);
          });

          it('should verify that first round constraints still hold for a2', () => {
              const a2 = md4_ff(
                  a1, msgStates[1].b, msgStates[1].c, msgStates[1].d,
                  modifiedMsg[4], md4FirstRoundBitShiftConstants[0]
              ); // TEST

              expect(a2).toEqual(msgStates[2].a);
              expect(verifyConstraints(
                  { word: a2, constraints: a2Constraints },
                  { a: a1, b: msgStates[1].b, c: msgStates[1].c, d: msgStates[1].d })
              ).toEqual(true);
          });
      });
   });

   describe('Differential', () => {
       it('should apply differential to message', () => {
           const result = applyDifferential(originalMsg); // TEST

           expect(result.length).toEqual(originalMsg.length);
           expect(result[1] - originalMsg[1]).toEqual(Math.pow(2, 31));
           expect(result[2] - originalMsg[2]).toEqual(Math.pow(2, 31) - Math.pow(2, 28));
           expect(result[12] - originalMsg[12]).toEqual(- Math.pow(2, 16));
           for (let i = 0; i <= 15; i++) {
               if (i != 1 && i != 2 && i != 12) {
                   expect(result[i] - originalMsg[i]).toEqual(0);
               }
           }
       });
   });

   describe('MD4 Collisions', () => {
       let msg1: number[], msg2: number[];

       beforeEach(() => {
           /*
           m1: 4d7a9c83 56cb927a b9d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f
                c69d71b3 f9e99198 d79f805e a63bb2e8 45dd8e31 97e31fe5 2794bf08 b9e8c3e9
           m'1: 4d7a9c83 d6cb927a 29d5a578 57a7a5ee de748a3c dcc366b3 b683a020 3b2a5d9f
                c69d71b3 f9e99198 d79f805e a63bb2e8 45dc8e31 97e31fe5 2794bf08 b9e8c3e9
            h*: 4d7e6a1d efa93d2d de05b45d 864c429b
            */
           msg1 = [
               0x4d7a9c83, 0x56cb927a, 0xb9d5a578, 0x57a7a5ee,
               0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f,
               0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8,
               0x45dd8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9
           ];
           msg2 = [
               0x4d7a9c83, 0xd6cb927a, 0x29d5a578, 0x57a7a5ee,
               0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f,
               0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8,
               0x45dc8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9
           ];
       });

       it('messages should have the same digest', () => {
           const expectedDigest = '4d7e6a1defa93d2dde05b45d864c429b';

           expect(core_md4(msg1, 512)).toEqual(core_md4(msg2, 512));
           expect(binl2hex(core_md4(msg2, 512))).toEqual(expectedDigest);
       });

       it('first & second round conditions hold for message', () => {
           // a1, b1, c1, d1
           a = md4_ff(a, b, c, d, msg1[0], 3 );
           expect(verifyConstraints(
               { word: a, constraints: a1Constraints }, { a, b: md4InitialState[1], c, d})
           ).toEqual(true);

           d = md4_ff(d, a, b, c, msg1[1], 7 );
           expect(verifyConstraints(
               { word: d, constraints: d1Constraints }, { a, b, c, d})
           ).toEqual(true);

           c = md4_ff(c, d, a, b, msg1[2], 11);
           expect(verifyConstraints(
               { word: c, constraints: c1Constraints }, { a, b, c, d})
           ).toEqual(true);

           b = md4_ff(b, c, d, a, msg1[3], 19);
           expect(verifyConstraints(
               { word: b, constraints: b1Constraints }, { a, b, c, d})
           ).toEqual(true);

           // a2, b2, c2, d2
           a = md4_ff(a, b, c, d, msg1[4], 3 );
           expect(verifyConstraints(
               { word: a, constraints: a2Constraints }, { a, b, c, d})
           ).toEqual(true);

           d = md4_ff(d, a, b, c, msg1[5], 7 );
           expect(verifyConstraints(
               { word: d, constraints: d2Constraints }, { a, b, c, d})
           ).toEqual(true);

           c = md4_ff(c, d, a, b, msg1[6], 11);
           expect(verifyConstraints(
               { word: c, constraints: c2Constraints }, { a, b, c, d})
           ).toEqual(true);

           b = md4_ff(b, c, d, a, msg1[7], 19);
           expect(verifyConstraints(
               { word: b, constraints: b2Constraints }, { a, b, c, d})
           ).toEqual(true);

           // a3, b3, c3, d3
           a = md4_ff(a, b, c, d, msg1[8], 3 );
           expect(verifyConstraints(
               { word: a, constraints: a3Constraints }, { a, b, c, d})
           ).toEqual(true);

           d = md4_ff(d, a, b, c, msg1[9], 7 );
           expect(verifyConstraints(
               { word: d, constraints: d3Constraints }, { a, b, c, d})
           ).toEqual(true);

           c = md4_ff(c, d, a, b, msg1[10], 11);
           expect(verifyConstraints(
               { word: c, constraints: c3Constraints }, { a, b, c, d})
           ).toEqual(true);

           b = md4_ff(b, c, d, a, msg1[11], 19);
           expect(verifyConstraints(
               { word: b, constraints: b3Constraints }, { a, b, c, d})
           ).toEqual(true);

           // a4, b4, c4, d4
           a = md4_ff(a, b, c, d, msg1[12], 3 );
           expect(verifyConstraints(
               { word: a, constraints: a4Constraints }, { a, b, c, d})
           ).toEqual(true);

           d = md4_ff(d, a, b, c, msg1[13], 7 );
           expect(verifyConstraints(
               { word: d, constraints: d4Constraints }, { a, b, c, d})
           ).toEqual(true);

           c = md4_ff(c, d, a, b, msg1[14], 11);
           expect(verifyConstraints(
               { word: c, constraints: c4Constraints }, { a, b, c, d})
           ).toEqual(true);

           b = md4_ff(b, c, d, a, msg1[15], 19);
           expect(verifyConstraints(
               { word: b, constraints: b4Constraints }, { a, b, c, d})
           ).toEqual(true);

           // a5
           a = md4_gg(a, b, c, d, msg1[0], 3 );
           expect(verifyConstraints(
               { word: a, constraints: a5Constraints }, { a, b, c, d})
           ).toEqual(true);
       });

       it('msg2 should be equal to msg1 with applied differential', () => {
           expect(applyDifferential(msg1)).toEqual(msg2);
       });

       it('should verify generated collision', () => {
           const hex1 = '388bb0f0563753c91139c7d2f1804f6ae3ccdda801e390bfdc3084357b8d6dab85483dd865a96797a82224ec5f43068a2b78aca94e53768f9328cebd7c5403c5';
           const hex2 = '388bb0f0563753491139c742f1804f6ae3ccdda801e390bfdc3084357b8d6dab85483dd865a96797a82224ec5f43068a2b78aba94e53768f9328cebd7c5403c5';

           expect(hex_md4_hex_input(hex1)).toEqual(hex_md4_hex_input(hex2));
       });
   });
});
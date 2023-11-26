import * as crypto from 'crypto';

// eslint-disable-next-line @typescript-eslint/camelcase
import { binl2hex, core_md4, hex2binl, md4_ff, md4_gg, safe_add } from '../set4/md4';

export type EqualToConstraint = null | '0' | '1' | 'a' | 'b' | 'c' | 'd';

export type WordWithConstraints = {
    word: number;
    constraints: ReadonlyArray<EqualToConstraint>;
};

export const md4FirstRoundBitShiftConstants = [3, 7, 11, 19];
export const md4SecondRoundBitShiftConstants = [3, 5, 9, 13];
export const md4InitialState = [1732584193, -271733879, -1732584194, 271733878];
export const maxWordSizeBits = Math.pow(2, 32);

/*
a1: a1,7 = b0,7
d1: d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
c1: c1,7 = 1, c1,8 = 1   , c1,11 = 0, c1,26=d1,26
b1: b1,7 = 1, b1,8  = 0  , b1,11 = 0,  b1,26 =0
*/
export const a1Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(6).fill(null), 'b'
];
export const d1Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(6).fill(null), '0', 'a', null, null, 'a'
];
export const c1Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(6).fill(null), '1', '1', null, null, '0', ...Array(14).fill(null), 'd'
];
export const b1Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(6).fill(null), '1', '0', null, null, '0', ...Array(14).fill(null), '0'
];
/*
a2: a2,8 = 1     , a2,11 = 1    , a2,26 = 0    , a2,14 = b1,14
d2: d2,14 = 0    , d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
c2: c2,13 = d2,13, c2,14 = 0    , c2,15 = d2,15, c2,19 = 0    , c2,20 = 0    , c2,21 = 1, c2,22 = 0
b2: b2,13 =1     , b2,14 =1     , b2,15 =0     , b2,17 = c2,17, b2,19 = 0    , b2,20 =0 , b2,21 = 0, b2,22 = 0
 */
export const a2Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(7).fill(null), '1', null, null, '1', null, null, 'b',
];
export const d2Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(13).fill(null), '0', null, null, null, null, 'a', 'a', 'a', 'a', null, null, null, '1'
];
export const c2Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(12).fill(null), 'd', '0', 'd', null, null, null, 'c', '0', '1', '0'
];
export const b2Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(12).fill(null), '1', '1', '0', null, 'c', null, '0', '0', '0', '0'
];
/*
a3: a3,13 = 1, a3,14 = 1, a3,15 = 1, a3,17 =     0, a3,19 = 0, a3,20 = 0, a3,21 = 0, a3,23 = b2,23, a3,22 = 1, a3,26 = b2,26
d3: d3,13 = 1, d3,14 = 1, d3,15 = 1, d3,17 =     0, d3,20 = 0, d3,21 = 1, d3,22 = 1, d3,23 = 0    , d3,26 = 1, d3,30 = a3,30
c3: c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 =     0, c3,23 = 0, c3,26 = 0, c3,30 = 1, c3,32 = d3,32
b3: b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1, b3,30 = 0, b3,32 = 0
*/
export const a3Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(12).fill(null), '1', '1', '1', null, '0', null, '0', '0', '0', '1', 'b', null, null, 'b'
];
export const d3Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(12).fill(null), '1', '1', '1', null, '0', null, null, '0', '1', '1', '0', null, null, '1',
    null, null, null, 'a'
];
export const c3Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(16).fill(null), '1', null, null, '0', '0', '0', '0', null, null, '0', null, null, null,
    '1', null, 'd'
];
export const b3Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(19).fill(null), '0', '1', '1', 'c', null, null, '1', null, null, null, '0', null, '0'
];
/*
a4: a4,23 = 0    , a4,26 = 0        , a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
d4: d4,23 = 0    , d4,26 = 0        , d4,27 = 1    , d4,29 = 1    , d4,30 = 0, d4,32 = 1
c4: c4,19 = d4,19, c4,23 = 1        , c4,26 = 1    , c4,27 = 0    , c4,29 = 0, c4,30 = 0
b4: b4,19 = 0    , b4,26 = c4,26 = 1, b4,27 = 1    , b4,29 = 1    , b4,30 = 0
 */
export const a4Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(22).fill(null), '0', null, null, '0', 'b', null, 'b', '1', null, '0'
];
export const d4Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(22).fill(null), '0', null, null, '0', '1', null, '1', '0', null, '1'
];
export const c4Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(18).fill(null), 'd', null, null, null, '1', null, null, '1', '0', null, '0', '0'
];
export const b4Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(18).fill(null), '0', null, null, null, null, null, null, 'c', '1', null, '1', '0'
];

/*
a5:  a5,19 = c4,19, a5,26 = 1    , a5,27 =0      ,a5,29 = 1     , a5,32 =1
d5:  d5,19 = a5,19, d5,26 = b4,26, d5,27 = b4,27 , d5,29 = b4,29, d5,32 = b4,32
 */
export const a5Constraints: ReadonlyArray<EqualToConstraint> = [
    ...Array(18), 'c', null, null, null, null, null, null, '1', '0', null, '1', null, null, '1'
];

function setIthBitToOne(i: number, computed: number): number {
    return computed | (1 << i);
}

function setIthBitToZero(i: number, computed: number): number {
    return computed & ~(1 << i);
}

function setIthBitToEqual(i: number, computed1: number, computed2: number): number {
    return computed1 ^ ((computed1 ^ computed2) & (1 << i));
}

export function applyConstraintsToWord(
    w: WordWithConstraints,
    otherWords: { [letter: string]: number }
): number {
    let computed = w.word;
    for (let i = 0; i < w.constraints.length; i++) {
        if (w.constraints[i]) {
            if (w.constraints[i] === '0') {
                computed = setIthBitToZero(i, computed);
            } else if (w.constraints[i] === '1') {
                computed = setIthBitToOne(i, computed);
            } else if (['a', 'b', 'c', 'd'].includes(w.constraints[i] as string)) {
                computed = setIthBitToEqual(i, computed, otherWords[w.constraints[i] as string]);
            }
        }
    }
    return computed;
}

export function rrot(num: number, cnt: number): number {
    return (num >>> cnt) | (num << (32 - cnt));
}

export function modifyMessageToMeetFirstRoundConstraints(
    msg: Array<number>,
    constraints: ReadonlyArray<{
        a: ReadonlyArray<EqualToConstraint>;
        b: ReadonlyArray<EqualToConstraint>;
        c: ReadonlyArray<EqualToConstraint>;
        d: ReadonlyArray<EqualToConstraint>;
    }>
): {
    words: Array<number>;
    states: Array<{ a: number; b: number; c: number; d: number}>;
} {
    const modified = [...msg];
    let a = md4InitialState[0]; let b = md4InitialState[1]; let c = md4InitialState[2]; let d = md4InitialState[3];
    let oldA: number, oldB: number, oldC: number, oldD: number;
    const states = [];
    for (let i = 0; i < 4; i++) {
        states.push({
            a, b, c, d
        });
        oldA = a;
        a = applyConstraintsToWord(
            {word: md4_ff(a, b, c, d, modified[4*i], md4FirstRoundBitShiftConstants[0]), constraints: constraints[i].a },
            {a, b, c, d}
            );
        modified[4*i] = rrot(a, md4FirstRoundBitShiftConstants[0]) - safe_add(oldA, ((b & c) | ((~b) & d)));
        modified[4*i] = modified[4*i] % maxWordSizeBits;

        oldD = d;
        d = applyConstraintsToWord(
            {word: md4_ff(d, a, b, c, modified[4*i + 1], md4FirstRoundBitShiftConstants[1]), constraints: constraints[i].d },
            {a, b, c, d}
            );
        modified[4*i + 1] = rrot(d, md4FirstRoundBitShiftConstants[1]) - safe_add(oldD, ((a & b) | ((~a) & c)));
        modified[4*i + 1] = modified[4*i + 1] % maxWordSizeBits;

        oldC = c;
        c = applyConstraintsToWord(
            {word: md4_ff(c, d, a, b, modified[4*i + 2], md4FirstRoundBitShiftConstants[2]), constraints: constraints[i].c },
            {a, b, c, d}
            );
        modified[4*i + 2] = rrot(c, md4FirstRoundBitShiftConstants[2]) - safe_add(oldC, ((d & a) | ((~d) & b)));
        modified[4*i + 2] = modified[4*i + 2] % maxWordSizeBits;

        oldB = b;
        b = applyConstraintsToWord(
            {word: md4_ff(b, c, d, a, modified[4*i + 3], md4FirstRoundBitShiftConstants[3]), constraints: constraints[i].b },
            {a, b, c, d}
            );
        modified[4*i + 3] = rrot(b, md4FirstRoundBitShiftConstants[3]) - safe_add(oldB, ((c & d) | ((~c) & a)));
        modified[4*i + 3] = modified[4*i + 3] % maxWordSizeBits;
    }
    states.push({
        a, b, c, d
    });
    return {
        words: modified,
        states
    };
}

export function verifyConstraints(
    w: WordWithConstraints,
    otherWords: { [letter: string]: number }
): boolean {
    let bit: number, correspondingBit: number;
    let verificationFailed = false;
    for (let i = 0; i < w.constraints.length; i++) {
        if (w.constraints[i]) {
            bit = w.word & (1 << i);
            if (w.constraints[i] === '0') {
                if (bit) {
                    verificationFailed = true;
                    break;
                }
            } else if (w.constraints[i] === '1') {
                if (!bit) {
                    verificationFailed = true;
                    break;
                }
            } else if (['a', 'b', 'c', 'd'].includes(w.constraints[i] as string)) {
                correspondingBit = otherWords[w.constraints[i] as string] & (1 << i);
                if (bit != correspondingBit) {
                    verificationFailed = true;
                    break;
                }
            }
        }
    }
    return !verificationFailed;
}

function modifyMessageToMeetA5Constraints(
    msg: Array<number>,
    states: Array<{ a: number; b: number; c: number; d: number}>
): Array<number> {
    const modified = [...msg];
    // a5 = (a4 + G(b4, c4, d4) + m[0] + 0x5a827999) << 3
    const a5 = applyConstraintsToWord(
        {word: md4_gg(states[4].a, states[4].b, states[4].c, states[4].d, modified[0],
                md4SecondRoundBitShiftConstants[0]), constraints: a5Constraints },
        {a: states[4].a, b: states[4].b, c: states[4].c, d: states[4].d}
    );
    // (a5 >> 3) - (a4 + ((b4 & c4) | (b4 & d4) | (c4 & d4)) + 0x5a827999) = NEW MSG[0]
    modified[0] = rrot(a5, md4SecondRoundBitShiftConstants[0]) - safe_add(
        states[4].a, safe_add(
            ((states[4].b & states[4].c) | (states[4].b & states[4].d) | (states[4].c & states[4].d)), 0x5a827999
        )
    );
    // recompute a1: a1 = md4_ff(a0, b0, c0, d0, NEW MSG[0], md4FirstRoundBitShiftConstants[0])
    states[1].a  = md4_ff(states[0].a, states[0].b, states[0].c, states[0].d, modified[0], md4FirstRoundBitShiftConstants[0]);
    // recompute msg blocks
    // NEW MSG[1] = rrot(d1, md4FirstRoundBitShiftConstants[1]) - safe_add(d0, ((NEW a1 & b0) | ((~NEW a1) & c0)));
    modified[1] = rrot(states[1].d, md4FirstRoundBitShiftConstants[1]) - safe_add(
        states[0].d, ((states[1].a & states[0].b) | ((~states[1].a) & states[0].c))
    );
    modified[1] = modified[1] % maxWordSizeBits;
    // NEW MSG[2] = rrot(c1, md4FirstRoundBitShiftConstants[2]) - safe_add(c0, ((d1 & NEW a1) | ((~d1) & b0)))
    modified[2] = rrot(states[1].c, md4FirstRoundBitShiftConstants[2]) - safe_add(
        states[0].c, ((states[1].d & states[1].a) | ((~states[1].d) & states[0].b))
    );
    modified[2] = modified[2] % maxWordSizeBits;
    // NEW MSG[3] = rrot(b1, md4FirstRoundBitShiftConstants[3]) - safe_add(b0, ((c1 & d1) | ((~c1) & NEW a1)))
    modified[3] = rrot(states[1].b, md4FirstRoundBitShiftConstants[3]) - safe_add(
        states[0].b, ((states[1].c & states[1].d) | ((~states[1].c) & states[1].a))
    );
    modified[3] = modified[3] % maxWordSizeBits;
    // NEW MSG[4] = rrot(a2, md4FirstRoundBitShiftConstants[0]) - safe_add(NEW a1, ((b1 & c1) | ((~b1) & d1)))
    modified[4] = rrot(states[2].a, md4FirstRoundBitShiftConstants[0]) - safe_add(
        states[1].a, ((states[1].b & states[1].c) | ((~states[1].b) & states[1].d))
    );
    modified[4] = modified[4] % maxWordSizeBits;
    return modified;
}

export function modifyMessageToMeetSecondRoundConstraints(
    msg: Array<number>,
    states: Array<{
        a: number;
        b: number;
        c: number;
        d: number;
    }>
): Array<number> {
    return modifyMessageToMeetA5Constraints(msg, states);
}

export function applyDifferential(msg: Array<number>): Array<number> {
    // △mi =0, 0 <= i <= 15, i  ̸= 1,2,12.
    const applied = [...msg];
    // △M = M′ −M = (△m0,△m1,......,△m15)
    // △m1 = 2^31,
    applied[1] = msg[1] + Math.pow(2, 31);
    // △m2 = 2^31 −2^28
    applied[2] = msg[2] + (Math.pow(2, 31) - Math.pow(2, 28));
    // △m12 = −2^16
    applied[12] = msg[12] - Math.pow(2, 16);
    return applied.map(w => w % maxWordSizeBits);
}

function generateCollision(): {
    msg1Hex: string;
    msg2Hex: string;
} {
    const firstRoundConstraints = [
        { a: a1Constraints, b: b1Constraints, c: c1Constraints, d: d1Constraints },
        { a: a2Constraints, b: b2Constraints, c: c2Constraints, d: d2Constraints },
        { a: a3Constraints, b: b3Constraints, c: c3Constraints, d: d3Constraints },
        { a: a4Constraints, b: b4Constraints, c: c4Constraints, d: d4Constraints },
    ];
    const nrOfGeneratedBytes = 64;
    let collisionFound = false;
    let bytes: Buffer, msg1: number[] = [], msg2: number[] = [], randomWords: number[] = [];
    let count = 0;
    while (!collisionFound) {
        bytes = crypto.randomBytes(nrOfGeneratedBytes);
        randomWords = hex2binl(bytes.toString('hex'));
        const { words, states } = modifyMessageToMeetFirstRoundConstraints(randomWords, firstRoundConstraints);
        msg1 = modifyMessageToMeetSecondRoundConstraints(words, states);
        msg2 = applyDifferential(msg1);
        if (binl2hex(core_md4([...msg1], nrOfGeneratedBytes * 8, md4InitialState)) ===
            binl2hex(core_md4([...msg2], nrOfGeneratedBytes * 8, md4InitialState))) {
            collisionFound = true;
        }
        if ((count % 1_000) === 0) {
            console.log(`Generated ${count} candidates`);
        }
        count++;
    }
    return {
        msg1Hex: binl2hex(msg1),
        msg2Hex: binl2hex(msg2)
    };
}

/*
generated collisions:
{
  msg1Hex: '41b94c4064c29fa627849899093128b46a19f94e8c2de9735e6ca161f2fca853c931db770fb853deb49ec00f35b6e0f2fa6603bc6719447d3bd3c62b13717af58',
  msg2Hex: '41b94c4064c29f2627849809093128b46a19f94e8c2de9735e6ca161f2fca853c931db770fb853deb49ec00f35b6e0f2fa6602bc6719447d3bd3c62b13717af58'
}

{
  msg1Hex: '815249ada7c7eb4902558e13908a1a6174910233137f155b47a23e5095d76367023039acefe386a78bef8d00db3a03a210c41a0df19feed24234930856b266f9',
  msg2Hex: '815249ada7c7ebc902558e83908a1a6174910233137f155b47a23e5095d76367023039acefe386a78bef8d00db3a03a210c4190df19feed24234930856b266f9'
}

{
  msg1Hex: '388bb0f0563753c91139c7d2f1804f6ae3ccdda801e390bfdc3084357b8d6dab85483dd865a96797a82224ec5f43068a2b78aca94e53768f9328cebd7c5403c5',
  msg2Hex: '388bb0f0563753491139c742f1804f6ae3ccdda801e390bfdc3084357b8d6dab85483dd865a96797a82224ec5f43068a2b78aba94e53768f9328cebd7c5403c5'
}
 */
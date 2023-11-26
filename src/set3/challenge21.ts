export type MT19937_BITS = 32 | 64;

export type SeededRng = () => number;

type MT19937_CONSTANTS = {
    w: number; n: number; m: number; r: number; a: number; u: number;
    d: number; s: number; b: number; t: number; c: number; l: number; f: number;
};

export const mt19937w32bitsConstants: MT19937_CONSTANTS = {
    w: 32, n: 624, m: 397, r: 31, a: 0x9908B0DF, u: 11, d: 0xFFFFFFFF,
    s: 7, b: 0x9D2C5680, t: 15, c: 0xEFC60000, l: 18, f: 1812433253
};

export function mt19937rng(seed: number, bits: MT19937_BITS, state?: Array<number>): SeededRng {
    if (bits === 64) {
        throw Error(`Not implemented`);
    }

    const constants = mt19937w32bitsConstants;
    let MT = Array(constants.n);
    let index = constants.n + 1;
    const lowerMask = 0x7fffffff;
    const upperMask = 0x80000000;

    function initializeState(): void {
        index = constants.n;
        MT[0] = seed >>> 0;
        let xorMT;
        for (let i = 1; i < constants.n; i++) {
            xorMT = MT[i-1] ^ (MT[i-1] >>> (constants.w - 2));
            MT[i] = (((((xorMT & 0xffff0000) >>> 16) * constants.f) << 16) + (xorMT & 0x0000ffff) * constants.f) + i;
            MT[i] = MT[i] >>> 0;
        }
    }

    function twist(): void {
        let x;
        let xA;
        let i;
        for (i = 0; i < constants.m; i++) {
            x = (MT[i] & upperMask) | (MT[i+1] & lowerMask);
            xA = (x & 0x1) ? constants.a : 0x0;
            MT[i] = MT[(i + constants.m) % constants.n] ^ (x >>> 1) ^ xA;
        }
        index = 0;
    }

    function extractNumber(): number {
        let y;
        if (index >= constants.n) {
            twist();
        }
        y = MT[index++];
        y ^= (y >>> constants.u);
        y ^= (y << constants.s) & constants.b;
        y ^= (y << constants.t) & constants.c;
        y ^= (y >>> constants.l);
        return y >>> 0;
    }

    if (state) {
        MT = state;
    } else {
        initializeState();
    }
    return extractNumber;
}



import {MT19937_BITS, SeededRng} from './challenge21';

export type RandomResult = {
    generated: number;
    seed: number;
};

async function sleep(millis: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, millis));
}

export async function randAfterRandomDelay(initRng: (seed: number, bits: MT19937_BITS) => SeededRng): Promise<RandomResult> {
    // Wait a random number of seconds between, I don't know, 40 and 1000.
    let delay = Math.floor(Math.random() * (100 - 40 + 1)) + 40;
    await sleep(delay * 1000);
    // Seeds the RNG with the current Unix timestamp
    const seed = Date.now();
    const rng = initRng(seed, 32);
    // Waits a random number of seconds again.
    delay = Math.floor(Math.random() * (100 - 40 + 1)) + 40;
    await sleep(delay * 1000);
    // Returns the first 32 bit output of the RNG.
    return {
        generated: rng(),
        seed: seed
    };
}
import {mt19937rng} from './challenge21';
import {randAfterRandomDelay, RandomResult} from './challenge22';

let result: RandomResult;
const startTime = Date.now();
randAfterRandomDelay(mt19937rng).then((generated) => {
    const stopTime = Date.now();
    result = generated;

    let rand;
    for (let i = startTime; i < stopTime; i++) {
        rand = mt19937rng(i, 32);
        if (rand() === result.generated) {
            if (i !== result.seed) {
                throw Error(`Seed ${i} did not match the expected one: ${result.seed}`);
            }
            console.log(`Discovered seed ${i}`);
        }
    }
});
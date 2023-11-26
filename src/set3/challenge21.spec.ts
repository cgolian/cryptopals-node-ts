import {mt19937rng, SeededRng} from './challenge21';

describe('Challenge 21', () => {
    let expected: Array<number>;
    let genRand: SeededRng;

    beforeEach(() => {
        expected = [
                3521569528, 1101990581, 1076301704, 2948418163, 3792022443,
                2697495705, 2002445460,  502890592, 3431775349, 1040222146,
                3582980688, 1840389745, 4282906414, 1327318762, 2089338664,
                4131459930, 3027134324, 2835148530, 1179416782, 1849001581,
                526320344, 2422121673, 2517840959, 2221714477,   55000521,
                591044015, 1168297933, 1971159042, 4039967188, 4139787488,
                122076017, 2865003221, 2757324559, 1140549535,  244059003,
                4193854726,   18931592, 4249850126,  312057759, 3675685089,
                280972886, 1066277295, 2046947247, 2429544615, 2740628128,
                2155829340, 3777224149, 1593303098, 3225103480, 1218072373,
                721749912, 3875531970,  800882885,  982222970,  764628465,
                1297523938, 1339440492, 2851444106, 2470351666, 3514079573,
                230610872, 3277181233, 2300098883, 3807585278, 3578508239,
                585251520, 1232810633, 3943696428, 2424229202, 4056955950,
                2946778364, 2827154017, 3581623447, 1646791240, 1641222099,
                984024840, 1406770355, 2596261903, 1495556502, 3270855102,
                1365682896, 3209664996, 1879158171, 3300120153, 2153622952,
                3729021385,  687831792, 2006786944, 3431925646, 1962505324,
                2824505801, 1348723856,  922631220, 3964570281, 2769770206,
                828731557, 4248452699, 2959523438,  906083865, 1323668227
            ];

        genRand = mt19937rng(1131464071, 32);
    });

    it('should throw for 64 bits', () => {
        expect(() => mt19937rng(5678, 64)).toThrow(Error); // TEST
    });

    it('should generate correct 100 "random" numbers for seed 5489', () => {
        const result = [];
        for (let i = 0; i < 100; i++) {
            result.push(genRand()); // TEST
        }
        expect(result).toEqual(expected);
    });
});
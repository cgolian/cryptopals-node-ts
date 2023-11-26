import {DiffieHellmanFunctions, initDiffieHellman} from "./challenge33";
import {CryptoBigNumber} from "./utils";

describe('Challenge 33', () => {
    describe('g = 5 and p = 37', () => {
        let fns: DiffieHellmanFunctions;

        beforeEach(() => {
            const p = new CryptoBigNumber(37);
            const g = new CryptoBigNumber(5);
            fns = initDiffieHellman(g, p);
        });

        it('session keys should be equal', () => {
            const pubKeyAlice = fns.generatePublicKey();
            const pubKeyBob = fns.generatePublicKey();

            const sessionKeyBob = fns.generateSessionKey(pubKeyAlice);
            const sessionKeyAlice = fns.generateSessionKey(pubKeyBob); // TEST

            expect(sessionKeyAlice).toEqual(sessionKeyBob);
        });
    });

    describe('NIST params', () => {
        let fns: DiffieHellmanFunctions;

        beforeEach(() => {
            const p = new CryptoBigNumber(`0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`, 16);
            const g = new CryptoBigNumber(2);
            fns = initDiffieHellman(g, p);
        });

        it('session keys should be equal', () => {
            const pubKeyAlice = fns.generatePublicKey();
            const pubKeyBob = fns.generatePublicKey();

            const sessionKeyBob = fns.generateSessionKey(pubKeyAlice);
            const sessionKeyAlice = fns.generateSessionKey(pubKeyBob); // TEST

            expect(sessionKeyAlice).toEqual(sessionKeyBob);
        });
    });
});
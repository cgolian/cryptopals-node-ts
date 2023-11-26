import { CryptoBigNumber } from "./utils";
import { initSRP } from "./challenge36";
import { BigNumber } from "bignumber.js";

describe('Challenge 36', () => {
    describe('SRP', () => {
        // parameters known to both Client and Server
        let N: BigNumber;
        let generator: BigNumber;
        let srp6multiplier: BigNumber;

        beforeEach(() => {
            N = new CryptoBigNumber(`0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`, 16);
            generator = new CryptoBigNumber(2);
            srp6multiplier = new CryptoBigNumber(3);
        });

        it('both sides should compute the same key', () => {
            const srpFunctions = initSRP(generator, N, srp6multiplier);

            // First, to establish a password p with server Steve,
            // client Carol picks a small random salt s, and computes x = H(s, p), v = gx
            const salt = new CryptoBigNumber(12675685687568752245);
            const password = "passw0rd";

            const privateKey = srpFunctions.computePrivateKey(salt, password);
            expect(privateKey.isInteger()).toEqual(true);

            const passwordVerifier = srpFunctions.computePasswordVerifier(privateKey);
            expect(passwordVerifier.isInteger()).toEqual(true);

            // Steve stores v and s, indexed by I, as Carol's password verifier and salt.
            // Then to perform a proof of password at a later date the following exchange protocol occurs:
            // Carol → Steve: generate random value a; send I and A = g^a
            const clientEphemeralKeys = srpFunctions.generateEphemeralKeysClient();
            expect(clientEphemeralKeys.privateKey.isInteger()).toEqual(true);
            expect(clientEphemeralKeys.publicKey.isInteger()).toEqual(true);

            // Steve → Carol: generate random value b; send s and B = kv + g^b
            const serverEphemeralKeys = srpFunctions.generateEphemeralKeysServer(passwordVerifier);
            expect(serverEphemeralKeys.publicKey.isInteger()).toEqual(true);
            expect(serverEphemeralKeys.privateKey.isInteger()).toEqual(true);

            // Both: u = H(A, B)
            const scramblingParameter = srpFunctions.computeScramblingParameter(
                clientEphemeralKeys.publicKey,
                serverEphemeralKeys.publicKey
            );
            expect(scramblingParameter.isInteger()).toEqual(true);

            // Carol: SCarol = (B − kg^x) = ... = (g^b)(a + ux)
            const sessionKeyClient = srpFunctions.computeSessionKeyClient(
                serverEphemeralKeys.publicKey,
                clientEphemeralKeys.privateKey,
                scramblingParameter,
                privateKey
            );

            // Steve: SSteve = (A*v^u)^b = ... = (g^b)(a + ux)
            const sessionKeyServer = srpFunctions.computeSessionKeyServer(
                clientEphemeralKeys.publicKey,
                serverEphemeralKeys.privateKey,
                passwordVerifier,
                scramblingParameter
            );

            expect(sessionKeyClient).toEqual(sessionKeyServer);
        });
    });
});
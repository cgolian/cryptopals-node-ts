import {DiffieHellmanFunctions, initDiffieHellman} from "./challenge33";
import {CryptoBigNumber, sha1} from "./utils";
import {decryptMsgWithSessionKey, encryptMsgWithSessionKey} from "./challenge34";
import { BigNumber } from "bignumber.js";

describe('Challenge 34', () => {
    describe('session key encryption/decryption', () => {
        let msg: Buffer;
        let sessionKey: Buffer;

        beforeEach(() => {
            const p = new CryptoBigNumber(`0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`, 16);
            const g = new CryptoBigNumber(2);
            const dh = initDiffieHellman(g, p);
            const publicKey = dh.generatePublicKey();
            sessionKey = dh.generateSessionKey(publicKey);
            msg = Buffer.from('As they croak, I see myself in the pistol smoke');
        });

        it('should encrypt/decrypt message using a session key', () => {
            const ciphertext = encryptMsgWithSessionKey(msg, sessionKey); // TEST
            const plaintext = decryptMsgWithSessionKey(ciphertext, sessionKey); // TEST

            expect(plaintext).toEqual(msg.toString());
        });
    });

    describe('MITM attack', () => {
        let p: BigNumber;
        let dh: DiffieHellmanFunctions;

        beforeEach(() => {
            p = new CryptoBigNumber(`0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`, 16);
            const g = new CryptoBigNumber(2);
            dh = initDiffieHellman(g, p);
        });

        it('should decrypt messages of both sides by injecting parameters', () => {
           // A->M Send "p", "g", "A"
           // M->B Send "p", "g", "p"
           // ...
           // B->M Send "B"
           // M->A Send "p"
           const sessionKeyAlice = dh.generateSessionKey(p);
           // A->M Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
           // M->B Relay that to B
           const msg = Buffer.from('Informer, ya\' no say daddy me Snow me I go blame');
           const ciphertext = encryptMsgWithSessionKey(msg, sessionKeyAlice);

           const bigZero = new BigNumber(0);
           const sessionKeyMITM = sha1(bigZero.toString(16));
           const decryptedByMITM = decryptMsgWithSessionKey(ciphertext, sessionKeyMITM);

           expect(sessionKeyMITM).toEqual(sessionKeyAlice);
           expect(decryptedByMITM).toEqual(msg.toString());
        });
    });
});
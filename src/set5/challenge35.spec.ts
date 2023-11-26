import { BigNumber } from "bignumber.js";
import {CryptoBigNumber, sha1} from "./utils";
import {DiffieHellmanFunctions, initDiffieHellman} from "./challenge33";
import {decryptMsgWithSessionKey, encryptMsgWithSessionKey} from "./challenge34";

describe('Challenge 35', () => {
    let g: BigNumber;
    let p: BigNumber;
    let dhAlice: DiffieHellmanFunctions;

    beforeEach(() => {
        p = new CryptoBigNumber(`0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`, 16);
        g = new CryptoBigNumber(2);
        dhAlice = initDiffieHellman(g, p);
    });

    describe('g = 1', () => {
        let sessionKeyAlice: Buffer;

        beforeEach(() => {
            const bigOne = new BigNumber(1);
            const dhBob = initDiffieHellman(bigOne, p);
            const publicKeyBob = dhBob.generatePublicKey();
            sessionKeyAlice = dhAlice.generateSessionKey(publicKeyBob);
        });

        // (1 ^ private key) mod p = 1 mod p
        it('MITM should be able to decrypt the message', () => {
            const bigOne = new BigNumber(1);
            const sessionKeyMITM = sha1(bigOne.toString(16));

            const msgFromAlice = 'Hello World 1';
            const encryptedMsgFromAlice = encryptMsgWithSessionKey(Buffer.from(msgFromAlice), sessionKeyAlice);
            const decryptedMsgMITM = decryptMsgWithSessionKey(encryptedMsgFromAlice, sessionKeyMITM); // TEST

            expect(msgFromAlice).toEqual(decryptedMsgMITM);
            expect(sessionKeyAlice).toEqual(sessionKeyMITM);
        });
    });

    describe('g = p', () => {
        let sessionKeyAlice: Buffer;

        beforeEach(() => {
            const dhBob = initDiffieHellman(p, p);
            const publicKeyBob = dhBob.generatePublicKey();
            sessionKeyAlice = dhAlice.generateSessionKey(publicKeyBob);
        });

        // (p ^ private key) mod p = 0 mod p
        it('MITM should be able to decrypt the message', () => {
            const bigZero = new BigNumber(0);
            const sessionKeyMITM = sha1(bigZero.toString(16));

            const msgFromAlice = 'Hello World 2';
            const encryptedMsgFromAlice = encryptMsgWithSessionKey(Buffer.from(msgFromAlice), sessionKeyAlice);
            const decryptedMsgMITM = decryptMsgWithSessionKey(encryptedMsgFromAlice, sessionKeyMITM); // TEST

            expect(msgFromAlice).toEqual(decryptedMsgMITM);
            expect(sessionKeyAlice).toEqual(sessionKeyMITM);
        });
    });

    describe('g = p - 1', () => {
        let sessionKeyAlice: Buffer;

        beforeEach(() => {
            const pMinusOne = new CryptoBigNumber(p.minus(1));
            const dhBob = initDiffieHellman(pMinusOne, p);
            const publicKeyBob = dhBob.generatePublicKey();
            sessionKeyAlice = dhAlice.generateSessionKey(publicKeyBob);
        });

        it('MITM should be able to decrypt the message', () => {
            const pMinusOne = new CryptoBigNumber(p.minus(1));
            // (p-1)^x mod p can be equal to 1 or p - 1
            const bigOne = new CryptoBigNumber(1);
            const possibleSessionKeyMITM1 = sha1(bigOne.toString(16));
            const possibleSessionKeyMITM2 = sha1(pMinusOne.toString(16));

            const msgFromAlice = 'Hello World 3';
            const encryptedMsgFromAlice = encryptMsgWithSessionKey(Buffer.from(msgFromAlice), sessionKeyAlice);
            let decryptedMsgMITM;
            try {
                decryptedMsgMITM = decryptMsgWithSessionKey(encryptedMsgFromAlice, possibleSessionKeyMITM1); // TEST
            } catch (e) {
                decryptedMsgMITM = decryptMsgWithSessionKey(encryptedMsgFromAlice, possibleSessionKeyMITM2); // TEST
            }

            expect(msgFromAlice).toEqual(decryptedMsgMITM);
        });
    });
});
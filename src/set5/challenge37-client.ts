import axios from 'axios';
import {initSRP} from './challenge36';
import {CryptoBigNumber, sha256} from './utils';
import { BigNumber } from 'bignumber.js';

// parameters known to both Client and Server
const N = new BigNumber(`0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`, 16);
const g = new BigNumber(2);
const k = new BigNumber(3);

const salt = CryptoBigNumber.random().times(Number.MAX_SAFE_INTEGER).integerValue(BigNumber.ROUND_FLOOR);

const srpFunctions = initSRP(g, N, k);

async function executeRegister(email: string, password: string): Promise<void> {
    const privateKey = srpFunctions.computePrivateKey(salt, password);
    const passwordVerifier = srpFunctions.computePasswordVerifier(privateKey);
    const registrationResponse = await axios.post('http://localhost:3000/register', {
        email,
        salt: salt.toString(16),
        passwordVerifier: passwordVerifier.toString(16)
    });
    if (registrationResponse.status !== 201) {
        throw Error(`Could not register ${email}`);
    }
}

async function executeAuthenticateWithoutPassword(email: string): Promise<void> {
    const challengeResponse = await axios.post('http://localhost:3000/challenge', {
        email
    });
    if (challengeResponse.status === 200
        && challengeResponse.data && challengeResponse.data.publicKey && challengeResponse.data.salt) {
        // we send A = 0, session key computed by server is then also going to be equal to 0
        const bigZero = new CryptoBigNumber(0);
        const digest = sha256(bigZero.toString(16));
        const fakeSessionKey = digest.toString('hex');
        const fakeProof = srpFunctions.computeSessionKeyHMAC(
            fakeSessionKey,
            salt
        );
        const authenticateResponse = await axios.post('http://localhost:3000/authenticate', {
            email,
            publicKey: bigZero.toString(16),
            proof: fakeProof
        });
        if (authenticateResponse.status !== 200) {
            throw Error(`Could not authenticate ${email}`);
        }
    } else {
        throw Error(`Could not challenge ${email}`);
    }
}

const username = "a@example.com";
const password = "passw0rd";

executeRegister(username, password)
    .then(() => {
        console.debug('Registered!');
        executeAuthenticateWithoutPassword(username)
            .then(() => {
                console.debug('Authenticated without password!');
            }).catch(() => {
                console.error('Could not authenticate')
            })
    }).catch(() => {
    console.error('Could not register');
});
import express = require('express');
import { CryptoBigNumber } from './utils';
import { BigNumber } from 'bignumber.js';
import {EphemeralKeys, initSRP} from "./challenge36";

// parameters known to both Client and Server
const N = new CryptoBigNumber(`0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`, 16);
const g = new CryptoBigNumber(2);
const k = new CryptoBigNumber(3);

const db: {
    [username: string]: {
        passwordVerifier: BigNumber;
        salt: BigNumber;
    };
} = {};

const cache: {
    [username: string]: EphemeralKeys;
} = {};

const srpFunctions = initSRP(g, N, k);

const app = express();
app.use(express.json());

// Register endpoints with Express
app.post('/register',
    (req, res, next) => {
        if (req.body && req.body.email && req.body.salt && req.body.passwordVerifier) {
            next();
        } else {
            console.error(`Invalid request body ${req.body}`);
            res.status(400).end();
        }
    },
    (req, res) => {
        const bigSalt = new CryptoBigNumber(req.body.salt, 16);
        const bigPasswordVerifier = new CryptoBigNumber(req.body.passwordVerifier, 16);
        // store (email, salt, password verifier) in DB
        db[req.body.email] = { salt: bigSalt, passwordVerifier: bigPasswordVerifier };
        res.status(201).end();
    }
);

app.post('/challenge',
    (req, res, next) => {
        if (req.body && req.body.email) {
            next();
        } else {
            res.status(400).end();
        }
    },
    (req, res) => {
        // try to retrieve salt & password verifier from the DB
        const record = db[req.body.email];
        if (record) {
            const serverKeys = srpFunctions.generateEphemeralKeysServer(record.passwordVerifier);
            cache[req.body.email] = {
                privateKey: serverKeys.privateKey,
                publicKey: serverKeys.publicKey
            };
            res
                .status(200)
                .json({
                    salt: record.salt.toString(16),
                    publicKey: serverKeys.publicKey.toString(16)
                })
                .end();
        } else {
            console.error(`Invalid request body ${req.body}`);
            res.status(400).end();
        }
    }
);

app.post('/authenticate',
    (req, res, next) => {
        if (req.body && req.body.email && req.body.publicKey && req.body.proof) {
            next();
        } else {
            console.error(`Invalid request body ${req.body}`);
            res.status(401).end();
        }
    },
    (req, res) => {
        const dbRecord = db[req.body.email];
        const cacheRecord = cache[req.body.email];
        if (dbRecord && cacheRecord) {
            const publicKeyClient = new BigNumber(req.body.publicKey, 16);
            const scramblingParameter = srpFunctions.computeScramblingParameter(
                publicKeyClient,
                cacheRecord.publicKey
            );

            const sessionKey = srpFunctions.computeSessionKeyServer(
                publicKeyClient,
                cacheRecord.privateKey,
                dbRecord.passwordVerifier,
                scramblingParameter
            );

            const serverSessionKeyHmac = srpFunctions.computeSessionKeyHMAC(
                sessionKey,
                dbRecord.salt
            );

            if (serverSessionKeyHmac === req.body.proof) {
                res.status(200).end();
            } else {
                console.error(`Client and server proof do not match`);
                res.status(401).end();
            }
        } else {
            console.error(`Missing records`);
            res.status(401).end();
        }
    }
);

app.listen(3000);
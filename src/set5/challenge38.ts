import BigNumber from "bignumber.js";

import {EphemeralKeys} from "./challenge36";
import {CryptoBigNumber, sha256, sha256hmac} from "./utils";

export interface SimplifiedSRPFunctions {
    /**
     * Compute private key
     * private key = hex(SHA256(salt | password))
     * @param salt
     * @param password
     */
    computePrivateKey(
        salt: BigNumber,
        password: string
    ): BigNumber;

    /**
     * Compute password verifier using a following formula:
     * password verifier = generator ^ private key mod N
     * @param privateKey
     */
    computePasswordVerifier(
        privateKey: BigNumber
    ): BigNumber;

    /**
     * Compute b & B
     * b = random number
     * B = (generator ^ b) mod N;
     */
    generateEphemeralKeysServer(): EphemeralKeys;

    /**
     * Compute a & A
     * a = random number
     * A = (generator ^ a) mod N;
     */
    generateEphemeralKeysClient(): EphemeralKeys;

    /**
     * Compute scrambling parameter
     * u = 128 bit random number
     */
    computeScramblingParameter(): BigNumber;

    /**
     * Compute session key for client:
     * S = (publicEphemeralKeyServer^(privateEphemeralKeyClient + scrambling parameter * private key) mod N)
     * session key = SHA256(S)
     *
     * @param publicEphemeralKeyServer
     * @param privateEphemeralKeyClient
     * @param scramblingParameter
     * @param privateKey
     */
    computeSessionKeyClient(
        publicEphemeralKeyServer: BigNumber,
        privateEphemeralKeyClient: BigNumber,
        scramblingParameter: BigNumber,
        privateKey: BigNumber
    ): string;

    /**
     * Compute session key for server:
     * S = (publicEphemeralKeyClient * passwordVerifier ^ scramblingParameter) ^ privateEphemeralKeyServer mod N
     * session key = SHA256(S);
     *
     * @param publicEphemeralKeyClient
     * @param privateEphemeralKeyServer
     * @param passwordVerifier
     * @param scramblingParameter
     */
    computeSessionKeyServer(
        publicEphemeralKeyClient: BigNumber,
        privateEphemeralKeyServer: BigNumber,
        passwordVerifier: BigNumber,
        scramblingParameter: BigNumber
    ): string;

    /**
     * Compute HMAC from the session key
     * @param sessionKey
     * @param salt
     */
    computeSessionKeyHMAC(
        sessionKey: string,
        salt: BigNumber
    ): string;
}

export function initSimplifiedSRP(generator: BigNumber, N: BigNumber): SimplifiedSRPFunctions {
    function computePrivateKey(
        salt: BigNumber,
        password: string
    ): BigNumber {
        const hexSalt = salt.toString(16);
        const digest = sha256(hexSalt.concat(password));
        return new CryptoBigNumber(digest.toString('hex'), 16);
    }

    function computePasswordVerifier(
        privateKey: BigNumber,
    ): BigNumber {
        return generator.exponentiatedBy(privateKey, N);
    }

    function generateEphemeralKeys(): EphemeralKeys {
        const privateKey = CryptoBigNumber.random().times(Number.MAX_SAFE_INTEGER).integerValue(BigNumber.ROUND_CEIL);
        const publicKey = generator.exponentiatedBy(privateKey, N);
        return {
            privateKey,
            publicKey
        }
    }

    function generateEphemeralKeysServer(): EphemeralKeys {
        return generateEphemeralKeys();
    }

    function generateEphemeralKeysClient(): EphemeralKeys {
        return generateEphemeralKeys();
    }

    function computeScramblingParameter(): BigNumber {
        return CryptoBigNumber.random().times(Number.MAX_SAFE_INTEGER).integerValue(BigNumber.ROUND_CEIL);
    }

    function computeSessionKeyClient(
        publicEphemeralKeyServer: BigNumber,
        privateEphemeralKeyClient: BigNumber,
        scramblingParameter: BigNumber,
        privateKey: BigNumber
    ): string {
        const aPlusUTimesX = privateEphemeralKeyClient.plus(scramblingParameter.times(privateKey)).modulo(N);
        const sessionKey = publicEphemeralKeyServer.exponentiatedBy(aPlusUTimesX, N);
        const sessionKeyDigest = sha256(sessionKey.toString(16));
        return sessionKeyDigest.toString('hex');
    }

    function computeSessionKeyServer(
        publicEphemeralKeyClient: BigNumber,
        privateEphemeralKeyServer: BigNumber,
        passwordVerifier: BigNumber,
        scramblingParameter: BigNumber
    ): string {
        const vToU = passwordVerifier.exponentiatedBy(scramblingParameter, N);
        const AtimesVToU = publicEphemeralKeyClient.times(vToU).modulo(N);
        const sessionKey = AtimesVToU.exponentiatedBy(privateEphemeralKeyServer, N);
        const sessionKeyDigest = sha256(sessionKey.toString(16));
        return sessionKeyDigest.toString('hex');
    }

    function computeSessionKeyHMAC(
        sessionKey: string,
        salt: BigNumber
    ): string {
        return sha256hmac(sessionKey, salt.toString(16));
    }

    return {
        computePrivateKey,
        computePasswordVerifier,
        generateEphemeralKeysServer,
        generateEphemeralKeysClient,
        computeScramblingParameter,
        computeSessionKeyClient,
        computeSessionKeyServer,
        computeSessionKeyHMAC,
    };
}

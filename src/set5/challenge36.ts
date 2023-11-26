import BigNumber from "bignumber.js";
import {CryptoBigNumber, sha256, sha256hmac} from "./utils";

export type EphemeralKeys = {
    publicKey: BigNumber;
    privateKey: BigNumber;
};

export interface SRPFunctions {
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
     * Compute password verifier using following formula:
     * password verifier = generator ^ private key mod N
     * @param privateKey
     */
    computePasswordVerifier(
        privateKey: BigNumber
    ): BigNumber;

    /**
     * Compute b & B
     * b = random number
     * B = (srp6multiplier * passwordVerifier + generator ^ b) % N;
     * @param passwordVerifier
     */
    generateEphemeralKeysServer(
        passwordVerifier: BigNumber
    ): EphemeralKeys;

    /**
     * Compute a & A
     * a = random number
     * A = (generator ^ a) mod N;
     */
    generateEphemeralKeysClient(): EphemeralKeys;

    /**
     * Compute scrambling parameter
     * scrambling parameter = SHA256(pubKeyClient | pubKeyServer)
     * @param publicEphemeralKeyClient
     * @param publicEphemeralKeyServer
     */
    computeScramblingParameter(
        publicEphemeralKeyClient: BigNumber,
        publicEphemeralKeyServer: BigNumber
    ): BigNumber;

    /**
     * Compute session key for client:
     * S = (B - srp6multiplier * g^x)^(a + u*x) % N
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
     * S = (A * v**u) ** b % N
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

export function initSRP(generator: BigNumber, N: BigNumber, srp6Multiplier: BigNumber): SRPFunctions {
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

    function generateEphemeralKeysServer(
        passwordVerifier: BigNumber
    ): EphemeralKeys {
        const privateKeyServer = CryptoBigNumber.random().times(Number.MAX_SAFE_INTEGER).integerValue(BigNumber.ROUND_CEIL);
        const kTimesV = srp6Multiplier.times(passwordVerifier);
        const gToX = generator.exponentiatedBy(privateKeyServer, N);
        const publicKeyServer = kTimesV.plus(gToX).modulo(N);
        return {
            publicKey: publicKeyServer,
            privateKey: privateKeyServer,
        };
    }

    function generateEphemeralKeysClient(): EphemeralKeys {
        const privateKeyClient = CryptoBigNumber.random().times(N).integerValue(BigNumber.ROUND_CEIL);
        const publicKeyClient = generator.exponentiatedBy(privateKeyClient, N);
        return {
            publicKey: publicKeyClient,
            privateKey: privateKeyClient
        };
    }

    function computeScramblingParameter(
        publicEphemeralKeyClient: BigNumber,
        publicEphemeralKeyServer: BigNumber
    ): BigNumber {
        const pubKeyClientHex = publicEphemeralKeyClient.toString(16);
        const pubKeyServerHex = publicEphemeralKeyServer.toString(16);
        const scramblingDigest = sha256(pubKeyClientHex.concat(pubKeyServerHex));
        return new CryptoBigNumber(scramblingDigest.toString('hex'), 16);
    }

    function computeSessionKeyClient(
        publicEphemeralKeyServer: BigNumber,
        privateEphemeralKeyClient: BigNumber,
        scramblingParameter: BigNumber,
        privateKey: BigNumber
    ): string {
        const kTimesgToX = srp6Multiplier.times(generator.exponentiatedBy(privateKey, N));
        const aPlusUTimesX = privateEphemeralKeyClient.plus(scramblingParameter.times(privateKey));
        const sessionKey = ((publicEphemeralKeyServer.minus(kTimesgToX).modulo(N)).exponentiatedBy(aPlusUTimesX, N));
        const sessionKeyDigest = sha256(sessionKey.toString(16));
        return sessionKeyDigest.toString('hex');
    }

    function computeSessionKeyServer(
        publicEphemeralKeyClient: BigNumber,
        privateEphemeralKeyServer: BigNumber,
        passwordVerifier: BigNumber,
        scramblingParameter: BigNumber,
    ): string {
        const ATimesvToU = publicEphemeralKeyClient.times(passwordVerifier.exponentiatedBy(scramblingParameter, N));
        const sessionKey = (ATimesvToU.exponentiatedBy(privateEphemeralKeyServer, N)).modulo(N);
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


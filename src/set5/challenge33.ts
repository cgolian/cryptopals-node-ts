import BigNumber from 'bignumber.js'
import {CryptoBigNumber, sha1} from './utils';

export interface DiffieHellmanFunctions {
    /**
     * private key = rand() mod modulus
     * public key = (generator ^ (private key)) mod modulus
     */
    generatePublicKey(): BigNumber;

    /**
     * session key = SHA1(public key ^ private key mod modulus)
     * @param publicKey public key
     */
    generateSessionKey(publicKey: BigNumber): Buffer;
}

export function initDiffieHellman(generator: BigNumber, modulus: BigNumber): DiffieHellmanFunctions {
    const privateKey = CryptoBigNumber.random().times(modulus).integerValue(BigNumber.ROUND_CEIL);

    function generatePublicKey(): BigNumber {
        return generator.exponentiatedBy(privateKey, modulus);
    }

    function generateSessionKey(publicKey: BigNumber): Buffer {
        const sessionKey = publicKey.exponentiatedBy(privateKey, modulus);
        return sha1(sessionKey.toString(16));
    }

    return {
        generatePublicKey,
        generateSessionKey,
    }
}

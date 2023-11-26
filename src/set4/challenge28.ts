import Sha1 from './sha1.js';

/**
 * Compute SHA-1 based MAC
 * @param message message
 * @param key key
 */
export function computeMACwSHA1(message: Buffer, key: Buffer): Buffer {
    const concatenated = Buffer.concat([key, message]);
    const computed = Sha1.hash(concatenated.toString('hex'), {
        msgFormat: 'hex-bytes',
        outFormat: 'hex'
    });
    return Buffer.from(computed, 'hex');
}

/**
 * Authenticate message by validating its MAC.
 * @param message message
 * @param mac message authentication code
 * @param key key
 */
export function verifyMACwSHA1(
    message: Buffer,
    mac: Buffer,
    key: Buffer
): boolean {
    const computedMac = computeMACwSHA1(message, key);
    return computedMac.equals(mac);
}
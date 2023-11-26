// eslint-disable-next-line @typescript-eslint/camelcase
import {hex_md4_hex_input} from './md4';
import {
    ForgedSecretPrefixMAC,
    padMessageMD,
    prepareTamperedInput,
    restoreHashFunctionState,
    SecretPrefixOracle
} from './challenge29';

/**
 * Compute MD4 based MAC
 * @param message message
 * @param key key
 */
export function computeMACwMD4(message: Buffer, key: Buffer): Buffer {
    const concatenated = Buffer.concat([key, message]);
    const computed = hex_md4_hex_input(concatenated.toString('hex'));
    return Buffer.from(computed, 'hex');
}

/**
 * Authenticate message by validating its MAC.
 * @param message message
 * @param mac message authentication code
 * @param key key
 */
export function verifyMACwMD4(
    message: Buffer,
    mac: Buffer,
    key: Buffer
): boolean {
    const computedMac = computeMACwMD4(message, key);
    return computedMac.equals(mac);
}

export function initMD4SecretPrefixOracle(secretKey: Buffer): SecretPrefixOracle {
    return {
        computeMAC: (msg: Buffer): Buffer => computeMACwMD4(msg, secretKey),
        verifyMAC: (msg: Buffer, mac: Buffer): boolean => verifyMACwMD4(msg, mac, secretKey)
    }
}

/**
 * Hash message with additional input by restoring its state using previous hash.
 *
 * @param msg message
 * @param mac message authentication code
 * @param keyLength length of the key used in secret prefix MAC
 * @param additionalInput additional input
 */
function hashAdditionalInputWMD4(
    msg: Buffer,
    mac: Buffer,
    keyLength: number,
    additionalInput: Buffer
): Buffer {
    const md4State = restoreHashFunctionState(mac, 'md4');
    const keyPlaceholder = Buffer.alloc(keyLength, 0x0);
    const msgWKey = padMessageMD(Buffer.concat([keyPlaceholder, msg]), 512, 'LE');
    const tamperedLengthBits = (msgWKey.length + additionalInput.length) * 8;
    const additionalMAC = hex_md4_hex_input(additionalInput.toString('hex'), md4State, tamperedLengthBits);
    return Buffer.from(additionalMAC, 'hex');
}

export function forgeSecretPrefixMACwMD4(
    msg: Buffer,
    mac: Buffer,
    additionalInput: Buffer,
    oracle: SecretPrefixOracle
): ForgedSecretPrefixMAC {
    let keyPlaceholder: Buffer;
    let forgedMAC: Buffer;
    let tamperedMsg: Buffer;
    // 100 is here just a guess
    for (let i = 1; i < 100; i++) {
        keyPlaceholder = Buffer.alloc(i, 0x0);
        forgedMAC = hashAdditionalInputWMD4(msg, mac, keyPlaceholder.length, additionalInput);
        tamperedMsg = prepareTamperedInput(keyPlaceholder, msg, additionalInput, 'LE');
        if (oracle.verifyMAC(tamperedMsg, forgedMAC)) {
            return {
                input: tamperedMsg,
                mac: forgedMAC,
                keyLength: keyPlaceholder.length
            };
        }
    }
    throw Error(`Could not forge input`);
}
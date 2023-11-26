import * as crypto from "crypto";
// eslint-disable-next-line @typescript-eslint/ban-ts-ignore
// @ts-ignore (dirty hack to bypass "[BigNumber Error] crypto unavailable" error
global.crypto = crypto;
import { BigNumber } from 'bignumber.js';

export const CryptoBigNumber = BigNumber.clone({
    CRYPTO: true, // cryptographically secure PRNG is used
    MODULO_MODE: BigNumber.EUCLID // remainder is always postiive
});

export function sha1(data: string): Buffer {
    return crypto.createHash('sha1')
        .update(data)
        .digest();
}

export function sha256(data: string): Buffer {
    return crypto.createHash('sha256')
        .update(data)
        .digest()
}

export function sha256hmac(data: string, key: string): string {
    return crypto.createHmac('sha256', key)
        .update(data)
        .digest('hex');
}
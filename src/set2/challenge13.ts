import * as crypto from 'crypto';
import {aes128EcbDecrypt, aes128EcbEncrypt, AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {padBlockPKCS7, stripPKCS7} from './challenge9';

const staticKey = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);

export function parseKVString(kvString: string): object {
    const pairs = kvString.split('&');
    const result: {[key: string]: string} = {};
    pairs.forEach((pair: string) => {
        const keyValue = pair.split('=');
        if (keyValue[0] && keyValue[1]) {
            result[keyValue[0]] = keyValue[1];
        }
    });
    return result;
}

export function encodeUserProfile(emailAddress: string): string {
    // remove metacharacters
    const sanitizedEmailAddress = emailAddress.replace(/[&=]/g, '');
    const userProfile = {
        email: sanitizedEmailAddress,
        uid: 10,
        role: 'user'
    };
    if (emailAddress === 'admin@mywebsite.com') {
        userProfile.role = 'admin';
        userProfile.uid = 1;
    }
    return `email=${userProfile.email}&uid=${userProfile.uid}&role=${
        userProfile.role
    }`;
}

export function encryptEncodedUserProfile(encodedUserProfile: Buffer): Buffer {
    return aes128EcbEncrypt(padBlockPKCS7(encodedUserProfile, AES_128_BLOCK_LENGTH_BYTES), staticKey);
}

export function decryptEncodedUserProfile(
    encryptedUserProfile: Buffer
): object {
    const encodedUserProfile = aes128EcbDecrypt(encryptedUserProfile, staticKey);
    return parseKVString(stripPKCS7(encodedUserProfile, AES_128_BLOCK_LENGTH_BYTES).toString());
}

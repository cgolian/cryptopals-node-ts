import {stripPKCS7} from './challenge9';

export function unpadBlockPKCS7(plaintext: Buffer, blockLength: number): Buffer {
    let validationFailed = false;
    if (plaintext.length % blockLength != 0) validationFailed = true;
    const lastBlock = plaintext.slice(plaintext.length - blockLength, plaintext.length);
    const lastByte = lastBlock[blockLength - 1];
    if (lastByte > blockLength || lastByte === 0x0) validationFailed = true;
    if (validationFailed || lastBlock.slice(lastBlock.length - lastByte, lastBlock.length).some(byte => byte != lastByte)) {
        throw Error(`Not valid PKCS7 padding`);
    }
    return stripPKCS7(plaintext, blockLength);
}
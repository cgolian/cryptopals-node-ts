import * as crypto from "crypto";

export function encryptMsgWithSessionKey(msg: Buffer, sessionKey: Buffer): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', sessionKey.slice(0, 16), iv);
    let encrypted = cipher.update(msg);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

export function decryptMsgWithSessionKey(msg: string, sessionKey: Buffer): string {
    const textParts = msg.split(':');
    const iv = Buffer.from(textParts[0], 'hex');
    textParts.shift();
    const encryptedText = Buffer.from(textParts.join(), 'hex');
    const decipher = crypto.createDecipheriv('aes-128-cbc', sessionKey.slice(0, 16), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}
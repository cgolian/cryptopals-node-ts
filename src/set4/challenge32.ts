import {HMACValidResponse, isHMACValid} from "./challenge31-client";

async function decryptHMACByteForPosition(file: string, signature: Buffer, position: number): Promise<number> {
    let decryptedByte = -1;
    // make the call for every possible byte
    let result: HMACValidResponse;
    const responseTimeForByteDictionary = Array(256);
    for (let i = 0; i < 256; i++) {
        signature[position] = i;
        result = await isHMACValid(file, signature.toString('hex'));
        if (result.success) return i;
        responseTimeForByteDictionary[i] = result.responseTime;
    }
    // select the one with the longest response time
    let minTime = (position + 1) * 5;
    responseTimeForByteDictionary.forEach((responseTime: number, idx: number) => {
        if (responseTime > minTime) {
            minTime = responseTime;
            decryptedByte = idx;
        }
    });
    return decryptedByte;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function findValidHMACForFile(file: string): Promise<string> {
    const signature = Buffer.alloc(20, 0x00);
    // for every character in HMAC digest
    for (let i = 0; i < signature.length; i++) {
        signature[i] = await decryptHMACByteForPosition(file, signature, i);
    }
    return Promise.resolve(signature.toString('hex'));
}
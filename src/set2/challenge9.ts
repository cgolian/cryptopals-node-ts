export function padBlockPKCS7(plaintext: Buffer, blockLength: number): Buffer {
    let blocks = Math.ceil(plaintext.length / blockLength);
    if (plaintext.length % blockLength === 0) {
        blocks++;
    }
    const paddingByte = blockLength - (plaintext.length % blockLength);
    const padded = Buffer.alloc(blocks * blockLength, paddingByte);
    plaintext.copy(padded, 0);
    return padded;
}

export function stripPKCS7(padded: Buffer, blockLength: number): Buffer {
    const lastBlock = padded.slice(padded.length - blockLength);
    const lastByte = lastBlock[lastBlock.length - 1];
    return padded.slice(0, padded.length - lastByte);
}
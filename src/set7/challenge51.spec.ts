import {
    CompressionOracle,
    initCompressionOracle,
    initPrepareRequest, recoverBlockCipherEncryptedSessionKeyUsingCompressionOracle,
    recoverStreamCipherEncryptedSessionKeyUsingCompressionOracle
} from './challenge51';

describe('Challenge 51', function () {
    describe('Prepare request', () => {
        let sessionKey: Buffer;
        let prepareRequest: (msgPayload: Buffer) => Buffer;

        beforeEach(() => {
            sessionKey = Buffer.from('TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=');
            prepareRequest = initPrepareRequest(sessionKey);
        });

        it('should construct the request', () => {
            const msg = Buffer.from('abcde');
            const expected = Buffer.from(`POST / HTTP/1.1\n` +
                `Host: hapless.com\nCookie: sessionid=${sessionKey.toString()}\n` +
                `Content-Length: ${msg.length}\n${msg.toString()}`);

            const result = prepareRequest(msg); // TEST

            expect(result).toEqual(expected);
        });
    });

    describe('Compression oracle', () => {
        let sessionKey: Buffer;
        let prepareRequest: (msgPayload: Buffer) => Buffer;

        beforeEach(() => {
            sessionKey = Buffer.from('TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=');
            prepareRequest = initPrepareRequest(sessionKey);
        });

        it('should compress CTR encrypted ciphertext', () => {
            const compressionOracle = initCompressionOracle(
                'aes-128-ctr',
                prepareRequest
            );

            const plaintext = Buffer.from('this message is going to be encrypted by AES in CTR mode');
            const req = prepareRequest(plaintext);

            const result = compressionOracle.getCiphertextLength(plaintext); // TEST

            expect(result).toBeLessThan(req.length);
        });

        it('should compress CBC encrypted ciphertext', () => {
            const compressionOracle = initCompressionOracle(
                'aes-128-cbc',
                prepareRequest
            );

            const plaintext = Buffer.from('this message is going to be encrypted by AES in CBC mode');
            const req = prepareRequest(plaintext);

            const result = compressionOracle.getCiphertextLength(plaintext); // TEST

            expect(result).toBeLessThan(req.length);
        });
    });

    describe('CTR compression oracle', () => {
       let sessionKey: Buffer;
       let compressionOracle: CompressionOracle;

       beforeEach(() => {
           sessionKey = Buffer.from('TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=');
           const prepareRequest = initPrepareRequest(sessionKey);
           compressionOracle = initCompressionOracle('aes-128-ctr', prepareRequest);
       });

       it('should recover session key encrypted with AES in CTR mode', () => {
           const result = recoverStreamCipherEncryptedSessionKeyUsingCompressionOracle(sessionKey.length, compressionOracle); // TEST

           expect(result).toEqual(sessionKey);
       });
    });

    describe('CBC compression oracle', () => {
        let sessionKey: Buffer;
        let compressionOracle: CompressionOracle;
        let prepareRequest: (payload: Buffer) => Buffer;

        beforeEach(() => {
            sessionKey = Buffer.from('TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=');
            prepareRequest = initPrepareRequest(sessionKey);
            compressionOracle = initCompressionOracle('aes-128-cbc', prepareRequest);
        });

        it('should recover session key encrypted with AES in CTR mode', () => {
            const result = recoverBlockCipherEncryptedSessionKeyUsingCompressionOracle(sessionKey.length, prepareRequest, compressionOracle); // TEST

            expect(result).toEqual(sessionKey);
        });
    });
});
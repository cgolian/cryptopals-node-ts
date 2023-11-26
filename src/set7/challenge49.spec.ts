import {
    CbcMacRequest,
    computeAes128CbcMac, editFirstBlock, initCbcMacClientServerProtocol,
    initCbcMacSimpleClientServerProtocol,
    SimpleCbcMacRequest,
    verifyAes128CbcMac
} from './challenge49';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {XORBitArrays} from "../set1/challenge2";
import {BitArray} from "../set1/challenge1";

describe('Challenge 49', () => {
    describe('CBC MAC', () => {
        let msg: Buffer;
        let key: Buffer;
        let iv: Buffer;
        let mac: Buffer;

        beforeEach(() => {
            key = Buffer.from('YELLOW SUBMARINE');
            iv = Buffer.from([0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4, 0x1, 0x2, 0x3, 0x4]);
            msg = Buffer.from('from=11011&to=220022&amount=1100');
            mac = computeAes128CbcMac(msg, iv, key);
        });

        it('MAC is one block in size', () => {
            expect(computeAes128CbcMac(msg, iv, key).length).toEqual(AES_128_BLOCK_LENGTH_BYTES); // TEST
        });

        it('should verify computed MAC', () => {
            expect(verifyAes128CbcMac(msg, mac, iv, key)).toEqual(true); // TEST
        });

        it('should not verify tampered MAC', () => {
            mac[1] = mac[1] + 1;
            expect(verifyAes128CbcMac(msg, mac, iv, key)).toEqual(false); // TEST
        });
    });

    describe('Simple protocol', () => {
        let serverHandleRequestFn: (msg: SimpleCbcMacRequest) => void;
        let clientCreateTxFn: (to: number, amount: number) => SimpleCbcMacRequest;

        beforeEach(() => {
            const key = Buffer.from('YELLOW SUBMARINE');

            const sp = initCbcMacSimpleClientServerProtocol(key);
            serverHandleRequestFn = sp.serverHandleRequest;
            clientCreateTxFn = sp.generateCreateTxFn(10000);
        });

        it('should handle valid request', () => {
            const req = clientCreateTxFn( 10001, 50.150);

            expect(() => serverHandleRequestFn(req)).not.toThrow(Error); // TEST
        });

        it('should throw for tampered request', () => {
            const req = clientCreateTxFn(10001, 50.150);
            req.mac[3] = req.mac[3] + 1;

            expect(() => serverHandleRequestFn(req)).toThrow(Error); // TEST
        });
    });

    describe('Edit first block', () => {
        let serverHandleRequestFn: (msg: SimpleCbcMacRequest) => void;
        let clientCreateTxFn: (to: number, amount: number) => SimpleCbcMacRequest;

        beforeEach(() => {
            const key = Buffer.from('YELLOW SUBMARINE');

            const sp = initCbcMacSimpleClientServerProtocol(key);
            serverHandleRequestFn = sp.serverHandleRequest;
            clientCreateTxFn = sp.generateCreateTxFn(11111100000);
        });

        it('should edit first block of the message', () => {
            // original message created by us
            const originalTx = clientCreateTxFn(1000000000001, 1000_000);
            // 22222200000 would be account of the victim
            const tamperedBlock = Buffer.from(`from=22222200000`);

            const result = editFirstBlock(originalTx, tamperedBlock); // TEST

            expect(() => serverHandleRequestFn(result)).not.toThrow(Error);
        });
    });

    describe('More complex protocol', () => {
        let serverHandleRequestFn: (msg: CbcMacRequest) => void;
        let clientCreateTxFn: (txList: { to: number; amount: number }[]) => CbcMacRequest;

        beforeEach(() => {
            const key = Buffer.from('YELLOW SUBMARINE');

            const sp = initCbcMacClientServerProtocol(key);
            serverHandleRequestFn = sp.serverHandleRequest;
            clientCreateTxFn = sp.generateClientCreateTx(10000001);
        });

        it('should handle valid request', () => {
            const txs = [{ to: 100001, amount: 50.1250}, { to: 100002, amount: 100.50}];
            const req = clientCreateTxFn(txs);

            expect(() => serverHandleRequestFn(req)).not.toThrow(Error); // TEST
        });

        it('should throw for tampered request', () => {
            const txs = [{ to: 100001, amount: 50.1250}, { to: 100002, amount: 100.50}];
            const req = clientCreateTxFn(txs);
            req.mac[3] = req.mac[3] + 1;

            expect(() => serverHandleRequestFn(req)).toThrow(Error); // TEST
        });
    });

    describe('Length extension attack', () => {
        let key: Buffer;
        let iv: Buffer;
        let serverHandleRequestFn: (msg: CbcMacRequest) => void;
        let victimsCreateTxFn: (txList: { to: number; amount: number }[]) => CbcMacRequest;

        beforeEach(() => {
            key = Buffer.from('Y3LL0W SU8MAR1N3');
            iv = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES, 0x0);
            const sp = initCbcMacClientServerProtocol(key);
            serverHandleRequestFn = sp.serverHandleRequest;
            victimsCreateTxFn = sp.generateClientCreateTx(10000000001);
        });

        it('should process tampered message', () => {
            // Prerequisite 0: initialization vector has to consist only of zero bytes
            // Prerequisite 1: attacker is able to sign following (or a similar) message:
            const maliciousBlock = Buffer.from(';2222222:1000000'); // 2222222 is attackers account
            const maliciousMAC = computeAes128CbcMac(maliciousBlock, iv, key);
            // victim creates a transaction
            const victimsReq = victimsCreateTxFn([{ to: 1001, amount: 50 }]);
            // we capture victims request
            const xored = XORBitArrays(BitArray.fromBuffer(victimsReq.mac), BitArray.fromBuffer(maliciousBlock));
            const tamperedReq = {
                // and append the block which redirects money to our account
                msg: Buffer.concat([victimsReq.msg, BitArray.toBuffer(xored)]),
                mac: maliciousMAC
            };
            // tampered message should be processed
            expect(() => serverHandleRequestFn(tamperedReq)).not.toThrow(Error); // TEST
        });
    });
});
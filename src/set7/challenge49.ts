import * as crypto from 'crypto';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';
import {XORBitArrays} from '../set1/challenge2';
import {BitArray} from '../set1/challenge1';
import {aes128CbcEncrypt} from '../set2/challenge10';

export function computeAes128CbcMac(msg: Buffer, iv: Buffer, key: Buffer): Buffer {
    const encrypted = aes128CbcEncrypt(msg, iv, key);
    return encrypted.slice(encrypted.length - AES_128_BLOCK_LENGTH_BYTES);
}

export function verifyAes128CbcMac(msg: Buffer, mac: Buffer, iv: Buffer, key: Buffer): boolean {
    const computed = computeAes128CbcMac(msg, iv, key);
    return computed.equals(mac)
}

export type SimpleCbcMacRequest = {
    msg: Buffer;
    iv: Buffer;
    mac: Buffer;
};

export function initCbcMacSimpleClientServerProtocol(key: Buffer): {
    serverHandleRequest: (msg: SimpleCbcMacRequest) => void;
    generateCreateTxFn: (from: number) => (to: number, amount: number) => SimpleCbcMacRequest;
} {
    function serverHandleRequest(req: SimpleCbcMacRequest): void {
        const computed = computeAes128CbcMac(req.msg, req.iv, key);
        if (!computed.equals(req.mac)) {
            throw Error(`TX could not be processed`);
        }
        // ... process request ...
    }

    function generateCreateTxFn(from: number): (to: number, amount: number) => SimpleCbcMacRequest {
        return function clientCreateTx(to: number, amount: number): SimpleCbcMacRequest {
            const msg = Buffer.from(`from=${from}&to=${to}&amount=${amount}`);
            const iv = crypto.randomBytes(AES_128_BLOCK_LENGTH_BYTES);
            const mac = computeAes128CbcMac(msg, iv, key);
            return { msg, iv, mac };
        }
    }

    return {
        serverHandleRequest,
        generateCreateTxFn,
    }
}

// replace first block and the IV of the original request
export function editFirstBlock(req: SimpleCbcMacRequest, tamperedBlock: Buffer): SimpleCbcMacRequest {
    const firstBlock = req.msg.slice(0, AES_128_BLOCK_LENGTH_BYTES);
    const xored = XORBitArrays(BitArray.fromBuffer(firstBlock), BitArray.fromBuffer(req.iv));
    const newIV = XORBitArrays(BitArray.fromBuffer(tamperedBlock), xored);
    const tamperedMsg = Buffer.concat([tamperedBlock, req.msg.slice(AES_128_BLOCK_LENGTH_BYTES)]);
    return {
        msg: tamperedMsg,
        iv: BitArray.toBuffer(newIV),
        mac: req.mac
    };
}

export type CbcMacRequest = {
    msg: Buffer;
    mac: Buffer;
};

type Tx = { to: number; amount: number };

export function initCbcMacClientServerProtocol(key: Buffer): {
    serverHandleRequest: (msg: CbcMacRequest) => void;
    generateClientCreateTx: (from: number) => (txList: ReadonlyArray<Tx>) => CbcMacRequest;
} {
    const iv = Buffer.alloc(AES_128_BLOCK_LENGTH_BYTES, 0x0);
    function serverHandleRequest(req: CbcMacRequest): void {
        const computed = computeAes128CbcMac(req.msg, iv, key);
        if (!computed.equals(req.mac)) {
            throw Error(`TX could not be processed`);
        }
        // ... process request ...
    }

    function generateClientCreateTx(from: number): (txList: ReadonlyArray<Tx>) => CbcMacRequest {
        return function clientCreateTx(txList: ReadonlyArray<Tx>): CbcMacRequest {
            const txString = txList.map((tx, idx) =>
                idx === txList.length - 1 ? `${tx.to}:${tx.amount}` : `${tx.to}:${tx.amount};`);
            const txBuffer = Buffer.from(`from=${from}&tx_list=${txString.join('')}`);
            return {
                msg: txBuffer,
                mac: computeAes128CbcMac(txBuffer, iv, key)
            };
        }
    }

    return {
        serverHandleRequest,
        generateClientCreateTx
    }
}



















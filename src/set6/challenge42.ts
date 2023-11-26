import * as crypto from "crypto";
import {RSAKey} from "../set5/challenge39";
import { CryptoBigNumber } from "../set5/utils";
import {cubeRoot} from "../set5/challenge40";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const asn1 = require('asn1-ber');

export interface PKCS1Padder {
    /**
     * Compute MD5 digest of input, encode it in ASN1 and pad it to length
     * @param input buffer input
     * @param length length in bits
     */
    pad(input: Buffer, length: number): Buffer;

    /**
     * Strip padding & decode from ASN1
     * @param input
     */
    strip(input: Buffer): Buffer;
}

export interface ASN1BERConverter {
    /**
     * Encode MD5 hash in ASN1 BER format
     * @param hash hash
     */
    encodeMd5Hash(hash: Buffer): Buffer;

    /**
     * Decode ASN1 BER encoded MD5 hash
     * @param berEncodedInput input
     */
    decodeMd5Hash(berEncodedInput: Buffer): Buffer;
}

export interface RSASignatureFunctions {
    /**
     * signed_message = pkcs1Pad(hash(message), privateKey.modulus) ^ privateKey.exponent mod privateKey.modulus
     *
     * @param message message to be signed
     * @param privateKey private key used when signing
     */
    signMessage(message: Buffer, privateKey: RSAKey): Buffer;

    /**
     * decrypted_message = stripPkcs1Pad(signature ^ publicKey.exponent mod publicKey.modulus, publicKey.modulus)
     * return true if hash(message) === decrypted_message
     *
     * @param message
     * @param signature
     * @param publicKey
     */
    verifySignature(message: Buffer, signature: Buffer, publicKey: RSAKey): boolean;
}

export interface RSASignatureForgeryFunctions {
    /**
     * Forge RSA signature with e = 3 by "faking" padding
     * @param message
     * @param modulusLength
     */
    forgeSignature(message: Buffer, modulusLength: number): Buffer;
}

export function initAsn1BerConverter(): ASN1BERConverter {
    const md5AlgorithmIdentifierOID = '1.2.840.113549.2.5';
    function encodeMd5Hash(hash: Buffer): Buffer {
        const writer = new asn1.BerWriter();
        // write DigestInfo
        writer.startSequence();
        // write DigestAlgorithmIdentifier
        writer.startSequence();
        // write OID algorithm
        writer.writeOID(md5AlgorithmIdentifierOID);
        // end DigestAlgorithmIdentifier
        writer.endSequence();
        // write Digest
        writer.writeBuffer(hash, asn1.Ber.OctetString);
        // end DigestInfo
        writer.endSequence();
        return writer.buffer;
    }

    function decodeMd5Hash(berEncodedInput: Buffer): Buffer {
        const reader = new asn1.BerReader(berEncodedInput);
        // read DigestInfo
        reader.readSequence();
        // read DigestAlgorithmIdentifier
        reader.readSequence();
        // read OID algorithm
        reader.readOID();
        // read digest
        return reader.readString(asn1.Ber.OctetString, true);
    }

    return {
        encodeMd5Hash,
        decodeMd5Hash
    };
}

export function initPKCS1Padder(): PKCS1Padder {
    const asn1Converter = initAsn1BerConverter();
    function pad(input: Buffer, length: number): Buffer {
        const padded = Buffer.alloc(length / 8);
        padded[0] = 0x00;
        padded[1] = 0x01;
        const hash = crypto.createHash('md5').update(input).digest();
        const asn1EncodedHash = asn1Converter.encodeMd5Hash(hash);
        const asn1Start = padded.length - asn1EncodedHash.length;
        asn1EncodedHash.copy(padded, asn1Start);
        padded[asn1Start - 1] = 0x00;
        padded.fill(0xFF, 2, asn1Start - 1);
        return padded;
    }

    function strip(input: Buffer): Buffer {
        if (input[0] != 0x00 || input[1] != 0x01) {
            throw Error(`Malformed input`);
        }
        const firstZeroByteIdx = input.indexOf(0x00, 2);
        if (firstZeroByteIdx === -1) {
            throw Error(`Malformed input`);
        }
        let byteIdx = firstZeroByteIdx;
        while (byteIdx < firstZeroByteIdx) {
            if (input[byteIdx] != 0xFF) {
                throw Error(`Malformed input`);
            }
            byteIdx++;
        }
        const asnIdx = byteIdx + 1;
        return asn1Converter.decodeMd5Hash(input.slice(asnIdx));
    }

    return {
        pad,
        strip
    }
}

export function initRSASignature(): RSASignatureFunctions {
    const padder = initPKCS1Padder();

    function signMessage(message: Buffer, privateKey: RSAKey): Buffer {
        const modulusBits = privateKey.modulus.toString(16).length * 4;
        const padded = padder.pad(message, modulusBits);
        const paddedNum = new CryptoBigNumber(padded.toString('hex'), 16);
        const signedNum = paddedNum.exponentiatedBy(privateKey.exponent, privateKey.modulus);
        return Buffer.from(signedNum.toString(16), 'hex');
    }

    function verifySignature(message: Buffer, signature: Buffer, publicKey: RSAKey): boolean {
        const signatureNum = new CryptoBigNumber(signature.toString('hex'), 16);
        const paddedNum = signatureNum.exponentiatedBy(publicKey.exponent, publicKey.modulus);
        // first byte 0x00 and 0 from 0x01 was stripped
        const paddedHex = '000'.concat(paddedNum.toString(16));
        const padded = Buffer.from(paddedHex, 'hex');
        const stripped = padder.strip(padded);
        const messageDigest = crypto.createHash('md5').update(message).digest();
        return stripped.equals(messageDigest);
    }

    return {
        signMessage,
        verifySignature
    }
}

export function initRSASignatureForgery(): RSASignatureForgeryFunctions {
    const asn1converter = initAsn1BerConverter();

    function forgeSignature(message: Buffer, modulusLength: number): Buffer {
        const messageDigest = crypto.createHash('md5').update(message).digest();
        const encoded = asn1converter.encodeMd5Hash(messageDigest);
        // construct buffer with minimum valid signature
        const forged = Buffer.alloc(modulusLength / 8, 0xFF);
        forged[0] = 0x00;
        forged[1] = 0x01;
        forged[2] = 0xFF;
        forged[3] = 0x00;
        encoded.copy(forged, 4);
        // compute cube root of numerical representation of buffer
        const forgedNum = new CryptoBigNumber(forged.toString('hex'), 16);
        // iterations should be probably a function of modulusLength
        let forgedNumCubeRoot = cubeRoot(forgedNum, 10_000);
        forgedNumCubeRoot = forgedNumCubeRoot.integerValue(CryptoBigNumber.ROUND_DOWN);
        return Buffer.from(forgedNumCubeRoot.toString(16), 'hex');
    }

    return {
        forgeSignature
    };
}
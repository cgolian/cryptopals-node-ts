import {
    ASN1BERConverter,
    initAsn1BerConverter,
    initPKCS1Padder, initRSASignature, initRSASignatureForgery,
    PKCS1Padder, RSASignatureForgeryFunctions,
    RSASignatureFunctions
} from './challenge42';
import * as crypto from 'crypto';
import {initRSA, RSAKeyPair} from "../set5/challenge39";

describe('Challenge 42', () => {
    describe('ASN 1 BER', () => {
       let asn1BerConverter: ASN1BERConverter;

       beforeEach(() => {
           asn1BerConverter = initAsn1BerConverter();
       });

       it('should encode MD5 digest', () => {
           const hash = crypto.createHash('md5').update('msg').digest();
           const expected = Buffer.from(
               '301E300A06082A864886F70D020504106E2BAAF3B97DBEEF01C0043275F9A0E7', 'hex');

           const result = asn1BerConverter.encodeMd5Hash(hash); // TEST

           expect(expected).toEqual(result);
       });

       it('should decode MD5 digest', () => {
           const hash = crypto.createHash('md5').update('msg').digest();
           const encoded = Buffer.from(
               '301E300A06082A864886F70D020504106E2BAAF3B97DBEEF01C0043275F9A0E7', 'hex');

           const result = asn1BerConverter.decodeMd5Hash(encoded); // TEST

           expect(result).toEqual(hash);
       });
    });

    describe('PKCS1', () => {
        let pkcs1Padder: PKCS1Padder;

        beforeEach(() => {
            pkcs1Padder = initPKCS1Padder();
        });

        it('should pad input', () => {
            const expected = Buffer.from(
                // PCKS1 padding
                '0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
                'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
                'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00' +
                // ASN1 BER encoded hashing
                '301E300A06082A864886F70D020504106E2BAAF3B97DBEEF01C0043275F9A0E7', 'hex');

            const input = Buffer.from('msg');
            const length = 1024;

            const result = pkcs1Padder.pad(input, length); // TEST

            expect(expected).toEqual(result);
        });

        it('should strip padding from input', () => {
            const expected = crypto.createHash('md5').update('msg').digest();
            const input = Buffer.from(
                // PCKS1 padding
                '0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
                'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
                'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00' +
                // ASN1 BER encoded hashing
                '301E300A06082A864886F70D020504106E2BAAF3B97DBEEF01C0043275F9A0E7', 'hex');

            const result = pkcs1Padder.strip(input); // TEST

            expect(expected).toEqual(result);
        });
    });

    xdescribe('RSA signature', () => {
        let rsaSignatureFunctions: RSASignatureFunctions;
        let rsaKeyPair: RSAKeyPair;

        beforeEach(() => {
            rsaSignatureFunctions = initRSASignature();
            const rsa = initRSA();
            rsaKeyPair = rsa.generateKeyPair(3, 512);
        });

        it('should sign & verify message', () => {
            const msg = Buffer.from('hi mom');
            const signature = rsaSignatureFunctions.signMessage(msg, rsaKeyPair.privateKey); // TEST
            const result = rsaSignatureFunctions.verifySignature(msg, signature, rsaKeyPair.publicKey); // TEST

            expect(result).toEqual(true);
        });
    });

    xdescribe('RSA signature forgery', () => {
        let rsaSignatureFunctions: RSASignatureFunctions;
        let rsaSignatureForgeryFunctions: RSASignatureForgeryFunctions;
        let rsaKeyPair: RSAKeyPair;

        beforeEach(() => {
            rsaSignatureFunctions = initRSASignature();
            rsaSignatureForgeryFunctions = initRSASignatureForgery();
            const rsa = initRSA();
            rsaKeyPair = rsa.generateKeyPair(3, 1024);
        });

        it('should verify message using a forged signature', () => {
            const msg = Buffer.from('hi mom');

            const signature =  rsaSignatureForgeryFunctions.forgeSignature(msg, 1024);
            const result = rsaSignatureFunctions.verifySignature(msg, signature, rsaKeyPair.publicKey); // TEST

            expect(result).toEqual(true);
        });
    });
});
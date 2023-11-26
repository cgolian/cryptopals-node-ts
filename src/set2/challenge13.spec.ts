import {decryptEncodedUserProfile, encodeUserProfile, encryptEncodedUserProfile, parseKVString} from './challenge13';
import {splitIntoBlocks} from '../set1/challenge6';
import {AES_128_BLOCK_LENGTH_BYTES} from '../set1/challenge7';

describe('Challenge 13', () => {
    describe('Helper functions', () => {
        it('Should parse k=v string.', () => {
            const expected = { role: 'admin' };

            const result = parseKVString('&role=admin&&&&&'); // TEST

            expect(expected).toEqual(result);
        });

        it('Should return encoded user profile.', () => {
            const expected = 'email=a@b.com&uid=10&role=user';

            const result = encodeUserProfile('a@b.com'); // TEST

            expect(expected).toEqual(result);
        });
    });

    it('Should assign admin role to regular user.', () => {
        const encryptedAdminProfile = encryptEncodedUserProfile(
            Buffer.from(encodeUserProfile('admin@mywebsite.com'))
        );

        const encryptedUserProfile = encryptEncodedUserProfile(
            Buffer.from(encodeUserProfile('aaaaaaaaa@bbbb.com'))
        );

        const adminProfileBlocks = splitIntoBlocks(encryptedAdminProfile, AES_128_BLOCK_LENGTH_BYTES);
        const adminRoleCiphertextBlock =
            adminProfileBlocks[adminProfileBlocks.length - 1];

        const encryptedTamperedUser = Buffer.alloc(encryptedUserProfile.length);
        encryptedUserProfile.copy(
            encryptedTamperedUser,
            0,
            0,
            encryptedUserProfile.length - AES_128_BLOCK_LENGTH_BYTES
        );
        adminRoleCiphertextBlock.copy(
            encryptedTamperedUser,
            encryptedUserProfile.length - AES_128_BLOCK_LENGTH_BYTES,
            0,
            AES_128_BLOCK_LENGTH_BYTES
        );

        const result: { role?: string } = decryptEncodedUserProfile(
            encryptedTamperedUser
        ); // TEST

        expect(result.role).toEqual('admin');
    });
});

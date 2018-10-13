#include <vector>
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <mbedtls/sha256.h>
#include "uint128_t.h"
#include "crypto.h"
#include <iostream>

using std::vector, std::array;

uint128_t leftRotate128(uint128_t n, unsigned int d) {
   return (n << d) | (n >> (128 - d));
}
 
uint128_t rightRotate128(uint128_t n, unsigned int d) {
   return (n >> d) | (n << (128 - d));
}

vector<u8> encryptAES(vector<u8> &plaintext, vector<u8> &output, array<u8, 16> &key, array<u8, 16> &iv) {
	mbedtls_aes_context curctx;
	mbedtls_aes_init(&curctx);
	mbedtls_aes_setkey_enc(&curctx, &key[0], 128);
	mbedtls_aes_crypt_cbc(&curctx, MBEDTLS_AES_ENCRYPT, plaintext.size(), &iv[0], &plaintext[0], &output[0]);
	return output;
}

/*
void encryptAES(vector<u8> &plaintext, array<u8, 16> &key, array<u8, 16> &iv, vector <u8> &output) {
    mbedtls_aes_context curctx;
    mbedtls_aes_init(&curctx);
    mbedtls_aes_setkey_enc(&curctx, &key[0], 128);
    mbedtls_aes_crypt_cbc(&curctx, MBEDTLS_AES_ENCRYPT, plaintext.size(), &iv[0], &plaintext[0], &output[0]);
}*/

vector<u8> decryptAES(vector<u8> &ciphertext, array<u8, 16> &key, array<u8, 16> &iv, u32 offset = 0, u32 size = 0) {
	if (size == 0) { size = ciphertext.size(); }
	mbedtls_aes_context curctx;
	mbedtls_aes_init(&curctx);
	mbedtls_aes_setkey_dec(&curctx, &key[0], 128);

	vector<u8> output(size);
	mbedtls_aes_crypt_cbc(&curctx, MBEDTLS_AES_DECRYPT, size, &iv[0], &ciphertext[offset], &output[0]);

	return output;
}

array<u8, 16> calculateCMAC(array<u8, 32> &input, array<u8, 16> &key) {
    const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_values(
        MBEDTLS_CIPHER_ID_AES,
        128,
        MBEDTLS_MODE_CBC
    );
    array<u8, 16> output;
    mbedtls_cipher_cmac(cipher_info, &key[0], key.size(), &input[0], input.size(), &output[0]);
    return output;
}

array<u8, 32> calculateSha256(vector<u8> &input) {
	array<u8, 32> output;

    mbedtls_sha256_context curctx;
    mbedtls_sha256_init(&curctx);
    mbedtls_sha256_starts(&curctx, 0);
    mbedtls_sha256_update(&curctx, &input[0], input.size());
    mbedtls_sha256_finish(&curctx, &output[0]);

	return output;
}

// NormalKey = (((KeyX ROL 2) XOR KeyY) + C1) ROR 41
array<u8, 16> keyScrambler(uint128_t KeyY, bool cmacYN) {
	uint128_t C(0x1FF9E9AAC5FE0408, 0x024591DC5D52768A);
	uint128_t KeyX(0x6FBB01F872CAF9C0, 0x1834EEC04065EE53);
	uint128_t CMAC_KeyX(0xB529221CDDB5DB5A, 0x1BF26EFF2041E875);
	
	uint128_t NormalKey = rightRotate128(((leftRotate128(cmacYN ? CMAC_KeyX : KeyX, 2) ^ KeyY) + C), 41);

	u64 lowerNK = NormalKey.lower();
	u64 upperNK = NormalKey.upper();

	array<u8, 16> NKBytes;

	for (int i = 0; i < 8; i++)
    	NKBytes[7 - i] = (upperNK >> (i * 8));
	for (int i = 0; i < 8; i++)
		NKBytes[15 - i] = (lowerNK >> (i * 8));

	return NKBytes;
}
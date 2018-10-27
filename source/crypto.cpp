#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <mbedtls/sha256.h>
#include <array>
#include "uint128_t.h"
#include "crypto.h"

using std::array;

uint128_t leftRotate128(uint128_t n, unsigned int d) {
   return (n << d) | (n >> (128 - d));
}
 
uint128_t rightRotate128(uint128_t n, unsigned int d) {
   return (n >> d) | (n << (128 - d));
}

void encryptAES(u8 *plaintext, u32 size, u8 *key, u8 *iv, u8 *output) {
	mbedtls_aes_context curctx;
	mbedtls_aes_init(&curctx);
	mbedtls_aes_setkey_enc(&curctx, key, 128);
	mbedtls_aes_crypt_cbc(&curctx, MBEDTLS_AES_ENCRYPT, size, iv, plaintext, output);
}

void decryptAES(u8 *ciphertext, u32 size, u8 *key, u8 *iv, u8 *output) {
	mbedtls_aes_context curctx;
	mbedtls_aes_init(&curctx);
	mbedtls_aes_setkey_dec(&curctx, key, 128);
	mbedtls_aes_crypt_cbc(&curctx, MBEDTLS_AES_DECRYPT, size, iv, ciphertext, output);
}

void calculateCMAC(u8 *input, u32 size, u8 *key, u8 *output) {
    const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_values(
        MBEDTLS_CIPHER_ID_AES,
        128,
        MBEDTLS_MODE_CBC
    );
    mbedtls_cipher_cmac(cipher_info, key, 128, input, size, output);
}

void calculateSha256(u8 *input, u32 size, u8 *output) {
    mbedtls_sha256_context curctx;
    mbedtls_sha256_init(&curctx);
    mbedtls_sha256_starts(&curctx, 0);
    mbedtls_sha256_update(&curctx, input, size);
    mbedtls_sha256_finish(&curctx, output);
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
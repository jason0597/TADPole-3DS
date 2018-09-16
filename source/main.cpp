#include <3ds.h>
#include <stdio.h>
#include <iostream>
#include <mbedtls/sha256.h>
#include "uint128_t.h"

void sha256() {
	u8 msgToHash[3] = {'H', 'e', 'y'};
	u8 output[32];
	mbedtls_sha256_ret(msgToHash, 3, output, 0);

	for (int i = 0; i < 32; i++) {
		printf("%X ", output[i]);
	}
}

uint128_t leftRotate128(uint128_t n, unsigned int d) {
   return (n << d) | (n >> (128 - d));
}
 
uint128_t rightRotate128(uint128_t n, unsigned int d) {
   return (n >> d) | (n << (128 - d));
}

void keyScrambler(uint128_t KeyY) {
	// C = 1FF9E9AAC5FE0408024591DC5D52768A
	// KeyX = 6FBB01F872CAF9C01834EEC04065EE53
	// KeyY = 49812D0400000000DA12650933D5D500
	//u8 C[16] = { 0x1f, 0xf9, 0xe9, 0xaa, 0xc5, 0xfe, 0x04, 0x08, 0x02, 0x45, 0x91, 0xdc, 0x5d, 0x52, 0x76, 0x8a };
	//u8 KeyX[16] = { 0x6f, 0xbb, 0x01, 0xf8, 0x72, 0xca, 0xf9, 0xc0, 0x18, 0x34, 0xee, 0xc0, 0x40, 0x65, 0xee, 0x53 };
	//u8 KeyY[16] = { 0x49, 0x81, 0x2d, 0x04, 0x00, 0x00, 0x00, 0x00, 0xda, 0x12, 0x65, 0x09, 0x33, 0xd5, 0xd5, 0x00 };

	// NormalKey = (((KeyX ROL 2) XOR KeyY) + C1) ROR 41
	uint128_t C(0x1FF9E9AAC5FE0408, 0x024591DC5D52768A);
	uint128_t KeyX(0x6FBB01F872CAF9C0, 0x1834EEC04065EE53);

	uint128_t NormalKey = rightRotate128(((leftRotate128(KeyX, 2) ^ KeyY) + C), 41);

	std::cout << std::hex << NormalKey << std::endl;
}

int main() {
	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);

	uint128_t KeyY(0x49812D0400000000, 0xDA12650933D5D500);
	keyScrambler(KeyY);

	while (aptMainLoop()) {
		hidScanInput();
		if (hidKeysDown() & KEY_START) break; 
		gfxFlushBuffers();
		gfxSwapBuffers();
		gspWaitForVBlank();
	}

	gfxExit();
	return 0;
}

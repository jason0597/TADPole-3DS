#include <3ds.h>
#include <vector>
#include <iostream>
#include <mbedtls/sha256.h>
#include "uint128_t.h"

using std::vector, std::cout;

uint128_t leftRotate128(uint128_t n, unsigned int d) {
   return (n << d) | (n >> (128 - d));
}
 
uint128_t rightRotate128(uint128_t n, unsigned int d) {
   return (n >> d) | (n << (128 - d));
}

vector<u8> keyScrambler(uint128_t KeyY) {
	uint128_t C(0x1FF9E9AAC5FE0408, 0x024591DC5D52768A);
	uint128_t KeyX(0x6FBB01F872CAF9C0, 0x1834EEC04065EE53);

	// NormalKey = (((KeyX ROL 2) XOR KeyY) + C1) ROR 41
	uint128_t NormalKey = rightRotate128(((leftRotate128(KeyX, 2) ^ KeyY) + C), 41);

	u64 lowerNK = NormalKey.lower();
	u64 upperNK = NormalKey.upper();

	vector<u8> NKBytes(16);

	for (int i = 0; i < 8; i++)
    	NKBytes[7 - i] = (upperNK >> (i * 8));
	for (int i = 0; i < 8; i++)
		NKBytes[15 - i] = (lowerNK >> (i * 8));

	return NKBytes;
}

void printBytes(vector<u8> bytes) {
	for (u32 i = 0; i < bytes.size(); i++) {
		cout << std::hex << ((bytes[i] < 0x10) ? "0" : "") << (int)bytes[i];
	}
	cout << std::dec << std::endl;
}

int main() {
	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);

	uint128_t KeyY(0x49812D0400000000, 0xDA12650933D5D500);
	vector<u8> NK = keyScrambler(KeyY);
	printBytes(NK);

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

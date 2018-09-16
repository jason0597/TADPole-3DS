#include <3ds.h>
#include <vector>
#include <iostream>
#include "uint128_t.h"
#include "crypto.h"

using std::vector, std::cout;

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
	vector<u8> NK = keyScrambler(KeyY, false);
	printBytes(NK);

	while (aptMainLoop()) {
		hidScanInput();
		if (hidKeysDown() & KEY_START) break; 
		gfxFlushBuffers();
		gfxSwapBuffers();
		gspWaitForVBlank();
	} gfxExit();
	
	return 0;
}

#include <3ds.h>
#include <vector>
#include <iostream>
#include <fstream>
#include "uint128_t.h"
#include "crypto.h"
#include "tadpole.h"

array<u8, 16> normalKey;
vector<u8> dsiwareBin;

#define PRINTBYTES(bytes) for (u32 i = 0; i < bytes.size(); i++) cout << std::hex << ((bytes[i] < 0x10) ? "0" : "") << (int)bytes[i]; cout << std::dec << std::endl;

/*

DataHandling // handles reading from the files on the disk to the map
Seedplanter  // it calls the relevant functions in order to:
             // decrypt, inject srl.nds/public.sav, fix hashes, sign, and then re-encrypt
TADPole// handles anything to do with the format of the dsiware itself, parsing the header
             // basically it implements whatever functions Seedplanter calls & depends on
Crypto       // handles raw crypto actions, generating CMAC, encrypt/decrypt, sign, etc.

*/

using std::vector, std::string, std::cout;

void writeAllBytes(string filename, vector<u8> &filedata) {
	std::ofstream curfile(filename, std::ios::out | std::ios::binary);
	curfile.write((char*)&filedata[0], filedata.size());
	curfile.close();
}

vector<u8> readAllBytes(string filename) {
	std::ifstream curfile(filename, std::ios::binary | std::ios::in | std::ios::ate);
	std::streampos filesize = curfile.tellg();

	vector<u8> output(filesize);
	curfile.seekg(0, std::ios::beg);
	curfile.read((char*)&output[0], filesize);
    curfile.close();

	return output;
}

void doStuff() {
	dsiwareBin = readAllBytes("484E4441.bin");

	uint128_t KeyY(0x49812D0400000000, 0xDA12650933D5D500);
	normalKey = keyScrambler(KeyY, false);

	vector<u8> decrypted = getDump(0, 0x4000);
	writeAllBytes("banner.bin", decrypted);
}

int main() {
	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);
	doStuff();
	cout << std::endl << "Done!";
	while (aptMainLoop()) {
		hidScanInput();
		if (hidKeysDown() & KEY_START) break; 
		gfxFlushBuffers();
		gfxSwapBuffers();
		gspWaitForVBlank();
	} gfxExit();
	
	return 0;
}

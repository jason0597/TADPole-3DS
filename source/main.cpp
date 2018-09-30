#include <3ds.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <cstring> // for memcpy()
#include <cmath> // for abs()
#include "uint128_t.h"
#include "crypto.h"
#include "tadpole.h"

using std::array, std::vector;

array<u8, 16> normalKey, normalKey_CMAC;
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

/*

1) decrypt srl.nds section
2) inject flipnote
3) calculate the CMAC of the SHA256 of the new srl.nds and put it at the block metadata
4) re-encrypt the srl.nds section
5) decrypt footer.bin section
6) fix the srl.nds hash, generate a new master hash, put it in the correct spot
7) insert the CTCert/APCert stuff
8) sign
9) calculate the CMAC of the SHA256 of the new footer.bin and put it at the block metadata
10) re-encrypt
11) ...
12) profit!

*/

using std::vector, std::string, std::cout, std::endl;

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

uint128_t parseMovableSed(vector<u8> movableSed) {
	array<u8, 0x10> NKBytes;
	memcpy(&NKBytes[0], &movableSed[0x110], 0x10);

	uint64_t lowerNK = 0, upperNK = 0;
	for (int i = 0; i < 8; i++)
		lowerNK |= ((u64)NKBytes[i] << ((7 - i) * 8));
	for (int i = 7; i < 16; i++)
		upperNK |= ((u64)NKBytes[i] << ((15 - i) * 8));

	uint128_t output(lowerNK, upperNK);
	return output;
}

void doStuff() {
	dsiwareBin = readAllBytes("484E4441.bin");
	vector<u8> ctcert_bin = readAllBytes("ctcert.bin");
	uint128_t keyY = parseMovableSed(readAllBytes("movable.sed"));
	normalKey = keyScrambler(keyY, false);
	normalKey_CMAC = keyScrambler(keyY, true);
	vector<u8> injection = readAllBytes("Ugoku Memo Chou (Japan).nds");

	array<u8, 16> allzero = array<u8, 16>(); // we'll need it later...

	// ========== BEGIN INJECTION PROCESSS ==========

	// === HEADER ===
	vector<u8> header = getDump(0x4020, 0xF0);
	// Read the magic value of the header
	if (header[0] != 0x33 || header[1] != 0x46 || header[2] != 0x44 || header[3] != 0x54) {
		cout << "DECRYPTION FAILED!!!" << endl;
	}
	array<u8, 4> flipnote_size_LE = {0x00, 0x88, 0x21, 0x00}; // the size of flipnote in little endian
	memcpy(&header[0x48 + 4], &flipnote_size_LE[0], 4);

	vector<u8> encrypted_header = encryptAES(header, normalKey, allzero);
	memcpy(&dsiwareBin[0x4020], &encrypted_header[0], header.size());

	array<u8, 32> header_hash = calculateSha256(header);
	array<u8, 16> header_cmac = calculateCMAC(header_hash, normalKey_CMAC);
	
	memcpy(&dsiwareBin[0x4020 + 0x110], &header_cmac[0], 16);
	memcpy(&dsiwareBin[0x4020 + 0x110 + 0x10], &allzero[0], 16);
	
	// === SRL.NDS ===
	// Basically, the srl.nds of DS Download play is right at the end of the TAD container
	// Because we don't care about what it contains, we can overwrite it directly with our new
	// flipnote srl.nds straight off the bat, without having to do any decryption
	// We of course need to extend our vector of dsiwareBin by the necessary difference in bytes
	// to accomodate the new flipnote srl.nds (which is 0x218800 in size!!)
	dsiwareBin.resize(dsiwareBin.size() + abs(dsiwareBin.size() - injection.size()));
	vector<u8> encrypted_srl_nds = encryptAES(injection, normalKey, allzero);
	memcpy(&dsiwareBin[0x5190], &encrypted_srl_nds[0], encrypted_srl_nds.size());

	array<u8, 32> flipnote_srl_nds_hash = calculateSha256(injection);
	array<u8, 16> flipnote_srl_nds_cmac = calculateCMAC(flipnote_srl_nds_hash, normalKey_CMAC);
	memcpy(&dsiwareBin[0x5190 + 0x218800], &flipnote_srl_nds_cmac[0], 0x10);
	memcpy(&dsiwareBin[0x5190 + 0x218800 + 0x10], &allzero[0], 0x10);

	// === FOOTER ===
	vector<u8> footer = getDump(0x4130, 0x4E0);
	writeAllBytes("footer.bin", footer);
	doSigning(ctcert_bin, footer);
}

int main() {
	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);
	doStuff();
	cout << endl << "Done!";
	while (aptMainLoop()) {
		hidScanInput();
		if (hidKeysDown() & KEY_START) break; 
		gfxFlushBuffers();
		gfxSwapBuffers();
		gspWaitForVBlank();
	} gfxExit();
	
	return 0;
}

#include <3ds.h>
#include <vector>
#include <cstring> // for memcpy()
#include <cmath> // for abs()
#include "crypto.h"
#include "tadpole.h"

#define WAITA() while (1) {hidScanInput(); if (hidKeysDown() & KEY_A) { break; } }

using std::array, std::vector;

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

u8 *readAllBytes(const char *filename, u32 *filelen) {
	FILE *fileptr = fopen(filename, "rb");
	if (fileptr == NULL) {
		printf("!!! Failed to open %s !!!\n", filename);
		WAITA();
		exit(-1);
	}
	fseek(fileptr, 0, SEEK_END);
	*filelen = ftell(fileptr);
	rewind(fileptr);

	u8 *buffer = (u8*)malloc(*filelen);

	fread(buffer, *filelen, 1, fileptr);
	fclose(fileptr);

	return buffer;
}

void writeAllBytes(const char* filename, u8 *filedata, u32 filelen) {
	FILE *fileptr = fopen(filename, "wb");
	fwrite(filedata, 1, filelen, fileptr);
	fclose(fileptr);
}

void doStuff() {
	u8 *dsiware, *ctcert, *movable, *injection;
	u32 dsiware_size, ctcert_size, movable_size, injection_size;

	printf("Reading 484E4441.bin\n");
	dsiware = readAllBytes("484E4441.bin", &dsiware_size);
	printf("Reading ctcert.bin\n");
	ctcert = readAllBytes("ctcert.bin", &ctcert_size);
	printf("Reading flipnote srl.nds\n");
	injection = readAllBytes("Ugoku Memo Chou (Japan).nds", &injection_size);
	printf("Reading & parsing movable.sed\n");
	movable = readAllBytes("movable.sed", &movable_size);

	printf("Scrambling keys\n");
	u8 normalKey[0x10], normalKey_CMAC[0x10];
	keyScrambler((movable + 0x110), false, normalKey);
	keyScrambler((movable + 0x110), true, normalKey_CMAC);
	for (int i = 0; i < 16; i++) {
		printf("%X", normalKey[i]);
	} printf("\n");
	for (int i = 0; i < 16; i++) {
		printf("%X", normalKey_CMAC[i]);
	} printf("\n");

	// === HEADER ===
	printf("Decrypting header\n");
	u8 *header = new u8[0xF0];
	getSection((dsiware + 0x4020), 0xF0, normalKey, header);
	
	if (header[0] != 0x33 || header[1] != 0x46 || header[2] != 0x44 || header[3] != 0x54) {
		printf("DECRYPTION FAILED!!!\n");
	}

	printf("Injecting new srl.nds size\n");
	u8 flipnote_size_LE[4] = {0x00, 0x88, 0x21, 0x00}; // the size of flipnote in little endian
	memcpy((header + 0x48 + 4), flipnote_size_LE, 4);

	printf("Placing back header\n");
	placeSection((dsiware + 0x4020), header, 0xF0, normalKey, normalKey_CMAC);
	delete[] header;

	// === SRL.NDS ===
	// Basically, the srl.nds of DS Download play is right at the end of the TAD container
	// Because we don't care about what it contains, we can overwrite it directly with our new
	// flipnote srl.nds straight off the bat, without having to do any decryption
	// We of course need to extend our vector of dsiwareBin by the necessary difference in bytes
	// to accomodate the new flipnote srl.nds (which is 0x218800 in size!!)
	printf("Resizing array\n");
	printf("Old DSiWare size: %X\n", dsiware_size);
	dsiware_size += abs(0x69BC0 - injection_size); // new TAD size = old TAD size + abs(old srl size - new srl size)
	printf("New DSiWare size: %X\n", dsiware_size);
	realloc(dsiware, dsiware_size);
	printf("Placing back srl.nds\n");
	placeSection((dsiware + 0x5190), injection, injection_size, normalKey, normalKey_CMAC);

	// === FOOTER ===
	printf("Decrypting footer\n");
	u8 *footer = new u8[0x4E0];
	getSection((dsiware + 0x4130), 0x4E0, normalKey, footer);
	printf("Signing footer\n");
	doSigning(ctcert, footer);

	printf("Placing back footer\n");
	placeSection((dsiware + 0x4130), footer, 0x4E0, normalKey, normalKey_CMAC);
	delete[] footer;

	writeAllBytes("484E4441.bin.patched", dsiware, dsiware_size);
}

int main() {
	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);

	printf("Press [A] to begin!\n\n");
	WAITA();

	doStuff();

	printf("\nDone!");

	while (aptMainLoop()) {
		hidScanInput();
		if (hidKeysDown() & KEY_START) break; 
		gfxFlushBuffers();
		gfxSwapBuffers();
		gspWaitForVBlank();
	} gfxExit();
	
	return 0;
}

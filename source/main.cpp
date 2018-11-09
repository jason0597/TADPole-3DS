#include <3ds.h>
#include <cstring>
#include <string>
#include <iostream>
#include "crypto.h"
#include "tadpole.h"
#include "frogtool.h"

PrintConsole topScreen, bottomScreen;
u8 flipnote_v0_hash[] = {0x7d, 0x22, 0xf4, 0x44, 0xeb, 0x35, 0x05, 0x46, 0x76, 0x9e, 0x38, 0x39, 0xa6, 0xb1, 0x21, 0xfc, 0xae, 0x65, 0xd0, 0x7c, 0x0e, 0xce, 0x67, 0xe9, 0x64, 0x07, 0x9b, 0xff, 0x52, 0xd5, 0x46, 0x1d};

using std::cout, std::string;

void error(string errormsg) {
	consoleSelect(&bottomScreen);
	cout << "\x1b[31m" << errormsg << "!\n" << "Press [START] to exit";

	while (1) {
		hidScanInput();
		if (hidKeysDown() & KEY_START) break; 
		gfxFlushBuffers();
		gfxSwapBuffers();
		gspWaitForVBlank();
	}

	exit(-1);
}

u8 *readAllBytes(string filename, u32 &filelen) {
	FILE *fileptr = fopen(filename.c_str(), "rb");
	if (fileptr == NULL) {
		error("Failed to open " + filename);
	}
	
	fseek(fileptr, 0, SEEK_END);
	filelen = ftell(fileptr);
	rewind(fileptr);

	u8 *buffer = (u8*)malloc(filelen);

	fread(buffer, filelen, 1, fileptr);
	fclose(fileptr);

	return buffer;
}

void writeAllBytes(string filename, u8 *filedata, u32 filelen) {
	FILE *fileptr = fopen(filename.c_str(), "wb");
	fwrite(filedata, 1, filelen, fileptr);
	fclose(fileptr);
}

void doStuff() {
	u8 *dsiware, *ctcert, *injection, *movable;
	u32 dsiware_size, ctcert_size, movable_size, injection_size;
	u8 header_hash[0x20] = {0}, srl_hash[0x20] = {0}, tmp_hash[0x20] = {0};
	u8 normalKey[0x10] = {0}, normalKey_CMAC[0x10] = {0};

	printf("Reading 484E4441.bin\n");
	dsiware = readAllBytes("/484E4441.bin", dsiware_size);
	if (dsiware_size != 454000) {
		error("Provided DS Download Play is not 454000 bytes in size");
	}
	printf("Reading ctcert.bin\n");
	ctcert = readAllBytes("/ctcert.bin", ctcert_size);
	if (ctcert_size != 0x19E) {
		error("Provided ctcert.bin is not 0x19E in size");
	}
	printf("Reading flipnote srl.nds\n");
	injection = readAllBytes("/srl.nds", injection_size);
	calculateSha256(injection, injection_size, tmp_hash);
	if (memcmp(tmp_hash, flipnote_v0_hash, 0x20) != 0) {
		error("Provided flipnote nds file's hash doesn't match");
	}
	printf("Reading & parsing movable.sed\n");
	movable = readAllBytes("/movable.sed", movable_size);
	if (movable_size != 320) {
		error("Provided movable.sed is not 320 bytes of size");
	}

	printf("Scrambling keys\n");
	keyScrambler((movable + 0x110), false, normalKey);
	keyScrambler((movable + 0x110), true, normalKey_CMAC);
	
	// === HEADER ===
	printf("Decrypting header\n");
	u8 *header = new u8[0xF0];
	getSection((dsiware + 0x4020), 0xF0, normalKey, header);
	
	if (header[0] != '3' || header[1] != 'F' || header[2] != 'D' || header[3] != 'T') {
		error("Decryption failed");
	}

	printf("Injecting new srl.nds size\n");
	u8 flipnote_size_LE[4] = {0x00, 0x88, 0x21, 0x00}; // the size of flipnote in little endian
	memcpy((header + 0x48 + 4), flipnote_size_LE, 4);

	printf("Placing back header\n");
	placeSection((dsiware + 0x4020), header, 0xF0, normalKey, normalKey_CMAC);

	printf("Calculating new header hash\n");
	calculateSha256(header, 0xF0, header_hash);
	delete[] header;

	// === SRL.NDS ===
	// Basically, the srl.nds of DS Download play is right at the end of the TAD container
	// Because we don't care about what it contains, we can overwrite it directly with our new
	// flipnote srl.nds straight off the bat, without having to do any decryption
	// We of course need to extend our dsiware array by the necessary difference in bytes
	// to accomodate the new flipnote srl.nds (which is 0x218800 in size)
	printf("Resizing array\n");
	printf("Old DSiWare size: %lX\n", dsiware_size);
	dsiware_size += (injection_size - 0x69BC0);
	printf("New DSiWare size: %lX\n", dsiware_size);
	dsiware = (u8*)realloc(dsiware, dsiware_size);
	printf("Placing back srl.nds\n");
	placeSection((dsiware + 0x5190), injection, injection_size, normalKey, normalKey_CMAC);

	printf("Calculating new srl.nds hash\n");
	calculateSha256(injection, injection_size, srl_hash);

	// === FOOTER ===
	printf("Decrypting footer\n");
	footer_t *footer = (footer_t*)malloc(SIZE_FOOTER);
	getSection((dsiware + 0x4130), 0x4E0, normalKey, (u8*)footer);

	printf("Fixing hashes\n");
	memcpy(footer->hdr_hash , header_hash, 0x20); //Fix the header hash
	memcpy(footer->content_hash[0], srl_hash, 0x20);	//Fix the srl.nds hash

	printf("Signing footer\n");
	Result res = doSigning(ctcert, footer);
	if (res < 0) {
		error("Signing failed");
	}
	
	printf("Placing back footer\n");
	placeSection((dsiware + 0x4130), (u8*)footer, 0x4E0, normalKey, normalKey_CMAC);
	delete[] footer;

	writeAllBytes("484E4441.bin.patched", dsiware, dsiware_size);

	free(dsiware);
	free(ctcert);
	free(injection);
	free(movable);
}

int main() {
	gfxInitDefault();
	consoleInit(GFX_TOP, &topScreen);
	consoleInit(GFX_BOTTOM, &bottomScreen);
	consoleSelect(&topScreen);
	
	AM_TWLPartitionInfo info;
	Result res = nsInit();
	printf("nsInit: %08X\n",(int)res);
	res = amInit();
	printf("amInit: %08X\n",(int)res);
	res = romfsInit();
	printf("romfsInit: %08X\n",(int)res);
	res = AM_GetTWLPartitionInfo(&info);
	printf("twlInfo: %08X\n\n",(int)res);

	u8 *buf = new u8[0x20000];

	printf("Press [A] to begin!\n\n");
	while (1) {hidScanInput(); if (hidKeysDown() & KEY_A) { break; } }

	export_tad(0x00048005484E4441, 5, buf, ".bin");
	doStuff();
	import_tad(0x00048005484E4441, 5, buf, ".bin.patched");

	NS_RebootToTitle(0, 0x00048005484E4441);

	printf("\nDone!");

	while (aptMainLoop()) {
		hidScanInput();
		if (hidKeysDown() & KEY_START) break; 
		gfxFlushBuffers();
		gfxSwapBuffers();
		gspWaitForVBlank();
	} 
	
	amExit();
	nsExit();
	gfxExit();
	
	return 0;
}

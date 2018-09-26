#include <3ds.h>
#include <vector>
#include <cstring> // for memcpy()
#include <iostream>
#include "crypto.h"

extern vector<u8> dsiwareBin;
extern array<u8,16> normalKey;

vector<u8> getDump(u32 data_offset, u32 size) {
	array<u8, 16> iv;
        memcpy(&iv[0], &dsiwareBin[data_offset + size + 0x10], 0x10);

        return decryptAES(dsiwareBin, normalKey, iv, data_offset, size);
}
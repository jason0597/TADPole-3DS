#include <3ds.h>
#include <vector>
#include <cstring> // for memcpy()
#include <iostream>
#include "crypto.h"
#include "ninty-233.hpp"

using std::vector, std::array;

extern vector<u8> dsiwareBin;
extern array<u8,16> normalKey;

vector<u8> getDump(u32 data_offset, u32 size) {
        array<u8, 16> iv;
        memcpy(&iv[0], &dsiwareBin[data_offset + size + 0x10], 0x10);

        return decryptAES(dsiwareBin, normalKey, iv, data_offset, size);
}

/*
typedef uint32_t element[8];

typedef struct {
	element x;
	element y;
} ec_point;
*/

// void ecdsa_sign(const BigUnsigned hash, const uint8_t * private_key, element r_out, element s_out);

void doSigning(vector<u8> &ctcert_bin, vector<u8> &footer) {
        vector<u8> hashes(13 * 0x20);
        memcpy(&hashes[0], &footer[0], 13 * 0x20);
        array<u8, 32> masterhash = calculateSha256(hashes);

        BigUnsigned masterhash_sha1 = sha1(&masterhash[0], 32);
}
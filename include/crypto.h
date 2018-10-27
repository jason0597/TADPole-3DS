#include <3ds.h>
#include <vector>
#include <array>
#include "uint128_t.h"

void encryptAES(u8 *plaintext, u32 size, u8 *key, u8 *iv, u8 *output);
void decryptAES(u8 *ciphertext, u32 size, u8 *key, u8 *iv, u8 *output);
void calculateCMAC(u8 *input, u32 size, u8 *key, u8 *output);
void calculateSha256(u8 *input, u32 size, u8 *output);
std::array<u8, 16> keyScrambler(uint128_t KeyY, bool cmacYN);
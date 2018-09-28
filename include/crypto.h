#include <3ds.h>
#include <vector>
#include <array>
#include "uint128_t.h"

using std::vector, std::array;

vector<u8> encryptAES(vector<u8> &plaintext, array<u8, 16> &key, array<u8, 16> &iv);
vector<u8> decryptAES(vector<u8> &ciphertext, array<u8, 16> &key, array<u8, 16> &iv, u32 offset, u32 size);
array<u8, 16> calculateCMAC(array<u8, 32> &input, array<u8, 16> &key);
array<u8, 32> calculateSha256(vector<u8> &input);
array<u8, 16> keyScrambler(uint128_t KeyY, bool cmacYN);
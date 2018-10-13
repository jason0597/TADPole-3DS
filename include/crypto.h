#include <3ds.h>
#include <vector>
#include <array>
#include "uint128_t.h"

std::vector<u8> encryptAES(std::vector<u8> &plaintext, std::vector<u8> &output, std::array<u8, 16> &key, std::array<u8, 16> &iv);
std::vector<u8> decryptAES(std::vector<u8> &ciphertext, std::array<u8, 16> &key, std::array<u8, 16> &iv, u32 offset, u32 size);
std::array<u8, 16> calculateCMAC(std::array<u8, 32> &input, std::array<u8, 16> &key);
std::array<u8, 32> calculateSha256(std::vector<u8> &input);
std::array<u8, 16> keyScrambler(uint128_t KeyY, bool cmacYN);
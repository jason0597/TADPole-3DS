#include <3ds.h>
#include <vector>
#include "uint128_t.h"

using std::vector;

vector<u8> encryptAES(vector<u8> plaintext, vector<u8> key, vector<u8> iv);
vector<u8> decryptAES(vector<u8> ciphertext, vector<u8> key, vector<u8> iv);
vector<u8> calculateCMAC(vector<u8> key, vector<u8> input);
vector<u8> keyScrambler(uint128_t KeyY, bool cmacYN);
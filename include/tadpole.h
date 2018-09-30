#include <3ds.h>
#include <vector>

using std::vector;

vector<u8> getDump(u32 data_offset, u32 size);
void doSigning(vector<u8> &ctcert_bin, vector<u8> &footer);
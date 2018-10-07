#include <3ds.h>
#include <vector>

std::vector<u8> getDump(u32 data_offset, u32 size);
void doSigning(std::vector<u8> &ctcert_bin, std::vector<u8> &footer);
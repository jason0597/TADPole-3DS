#include <3ds.h>
#include <vector>

std::vector<u8> getSection(u32 data_offset, u32 size);
void doSigning(std::vector<u8> &ctcert_bin, std::vector<u8> &footer);
void placeSection(std::vector<u8> &section, u32 offset);
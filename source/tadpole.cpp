#include <3ds.h>
#include <vector>
#include "crypto.h"
#include <iostream>

using std::vector, std::cout;

extern vector<u8> dsiwareBin;
extern array<u8,16> normalKey;

/*
private static byte[] getDump(Crypto crypto, byte[] DSiWare, int data_offset, int size) throws InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] key =  crypto.normalKey;
        byte[] iv = new byte[0x10];
        byte[] enc = new byte[size];

        System.arraycopy(DSiWare, data_offset, enc, 0, size);
        System.arraycopy(DSiWare, (data_offset + size + 0x10), iv, 0, 0x10);

        return crypto.decryptMessage(enc, key, iv);
*/

#define PRINTBYTES(bytes) for (u32 i = 0; i < bytes.size(); i++) cout << std::hex << ((bytes[i] < 0x10) ? "0" : "") << (int)bytes[i]; cout << std::dec << std::endl;

vector<u8> getDump(u32 data_offset, u32 size) {
	array<u8, 16> iv;
        for (int i = (data_offset + size + 0x10); i < (data_offset + size + 0x20); i++)
                iv[i - (data_offset + size + 0x10)] = dsiwareBin[i];

        PRINTBYTES(iv);
        std::cout << std::hex << (int)dsiwareBin[data_offset] << (int)dsiwareBin[data_offset + size] << std::endl;
        return decryptAES(dsiwareBin, data_offset, size, normalKey, iv);
}
#include <3ds.h>
#include <vector>
#include "crypto.h"

using std::vector;

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

//vector<u8> getDump(u32 data_offset, u32 size) {
	
        
        //return decryptAES(vector<u8> ciphertext, vector<u8> key, vector<u8> iv);
//}
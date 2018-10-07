#include <3ds.h>
#include <vector>
#include <cstring> // for memcpy()
#include <cstdio>
#include <iostream>
#include "crypto.h"

using namespace std;

#define PRINTBYTES(bytes) for (u32 i = 0; i < bytes.size(); i++) cout << std::hex << ((bytes[i] < 0x10) ? "0" : "") << (int)bytes[i]; cout << std::dec << std::endl;

typedef uint32_t element[8];
void ninty_233_ecdsa_sign_sha256(uint8_t * input, int length, const uint8_t * private_key, element r_out, element s_out);
void elem_to_os(const element src, uint8_t * output_os);

using std::vector, std::array;

extern vector<u8> dsiwareBin;
extern array<u8,16> normalKey;

vector<u8> getDump(u32 data_offset, u32 size) {
        array<u8, 16> iv;
        memcpy(&iv[0], &dsiwareBin[data_offset + size + 0x10], 0x10);

        return decryptAES(dsiwareBin, normalKey, iv, data_offset, size);
}

/*

1) Read in the Public/Private key pair from the ctcert.bin into the KeyPair object
2) Copy the ctcert.bin to the CTCert section of the footer.bin
3) Take the 13 hashes at the top, and hash them all to get a single master hash of all the contents of the DSiWare container
4) Sign that hash. Retrieve the ECDSA (X, Y) coordinates in the form of byte arrays, each one of size 0x1E.
   If the points retrieved are not 0x1E in size, add padding 0s at the start. Then, take those two arrays,
   combine them and you'll get a single big byte array of size 0x3C. Place that in the correct spot for the footer. (it's placed
   immediately after the 13 hashes, i.e. 13 * 0x20 == 0x1A0)

5) Make a new byte array of size 0x40. Then, fill it up with this formula:
    snprintf(your_byte_array, 0x40, "%s-%s", ctcert->issuer, ctcert->key_id);
6) Copy that byte array into the issuer section for the APCert (it's at offset 0x80 relative to the start of the APCert)
7) Hash the APCert's bytes in the range of 0x80 to 0x180 (in total 0x100 bytes).
   Essentially skip the signature portion of the APCert (cause you don't sign a signature)
8) Sign that hash you just created with your KeyPair. Do the same coordinate retrieval process as for step 4.
9) Take your coordinates byte array (2 * 0x1E = 0x3C in size), and place it in the signature
   section of the APCert (it's at offset 0x04 relative to the start of the APCert)
10) Copy the public key byte array into the APCert's public key field (it's at offset 0x108 relative to the start of the APCert)

*/

static void println(string str) {
	cout << str << endl;
}

void doSigning(vector<u8> &ctcert_bin, vector<u8> &footer) {
        u32 totalhashsize = 13 * 0x20;
        memcpy(&footer[totalhashsize + 0x1BC], &ctcert_bin[0], 0x180);

        element r, s;
        println("Signing master hash");
        ninty_233_ecdsa_sign_sha256(&footer[0x00], (totalhashsize), &ctcert_bin[0x180], r, s);

        println("Writing signature to footer");
        array<u8, 0x3C> signature = {};
        elem_to_os(r, &signature[0x00]);
        elem_to_os(s, &signature[0x1E]);
        memcpy(&footer[totalhashsize], &signature[0], 0x3C);

        println("Fixing APCert issuer");
        memset(&footer[0x1DC + 0x80], 0, 0x40);
	//snprintf(apcert->issuer, 0x40, "%s-%s", ctcert->issuer, ctcert->key_id);
        snprintf((char*)&footer[0x1DC + 0x80], 0x40, "%s-%s", &footer[totalhashsize + 0x1BC + 0x80], &footer[totalhashsize + 0x1BC + 0xC0]);

        println("Signing APCert issuer");
        element r2, s2;
        ninty_233_ecdsa_sign_sha256(&footer[0x1DC + 0x80], 0x100, &ctcert_bin[0x180], r2, s2);
        println("Finished");
        elem_to_os(r2, &signature[0x00]);
        elem_to_os(s2, &signature[0x1E]);
        println("Writing APCert to footer");
        memcpy(&footer[0x1DC], &signature[0], 0x3C);

        println("Writing public key to APcert");
        memcpy(&footer[0x1DC + 0x108], &ctcert_bin[0x108], 0x3C);
}
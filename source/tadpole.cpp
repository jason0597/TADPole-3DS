#include <3ds.h>
#include <cstring> // for memcpy()
#include <cstdio>
#include <vector>
#include <array>
#include "crypto.h"

using std::vector, std::array;

typedef uint32_t element[8];
void ninty_233_ecdsa_sign_sha256(uint8_t * input, int length, const uint8_t * private_key, element r_out, element s_out);
void elem_to_os(const element src, uint8_t * output_os);

void getSection(u8 *dsiware_pointer, u32 section_size, u8 *key, u8 *output) {
        decryptAES(dsiware_pointer, section_size, key, (dsiware_pointer + section_size + 0x10), output);
}

void placeSection(u8 *dsiware_pointer, u8 *section, u32 section_size, u8 *key, u8 *key_cmac) {
        u8 allzero[0x10]= {0};

        printf("Encrypting section and placing\n");
        encryptAES(section, section_size, key, allzero, dsiware_pointer);

        u8 section_hash[0x20];
        printf("Calculating section hash\n");
        calculateSha256(section, section_size, section_hash);

        printf("Old CMAC: ");
        for (int i = 0; i < 16; i++) { printf("%02X", (dsiware_pointer + section_size)[i]); } printf("\n");
        u8 section_cmac[0x20];
        printf("Uninitialized array: ");
        for (int i = 0; i < 16; i++) { printf("%02X", section_cmac[i]); } printf("\n");
        printf("Calculating section CMAC\n");
        calculateCMAC(section_hash, 0x20, key_cmac, section_cmac);

        printf("New CMAC: ");
        for (int i = 0; i < 16; i++) { printf("%02X", section_cmac[i]); } printf("\n");
        printf("Copying new CMAC\n");
        memcpy((dsiware_pointer + section_size), section_cmac, 0x10);
        printf("New placed CMAC: ");
        for (int i = 0; i < 16; i++) { printf("%02X", (dsiware_pointer + section_size)[i]); } printf("\n");

        printf("Writing all-zero IV\n");
        memset((dsiware_pointer + section_size + 0x10), 0, 0x10);
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

void doSigning(u8 *ctcert_bin, u8 *footer) {
        u32 totalhashsize = 13 * 0x20;
        memcpy(&footer[totalhashsize + 0x1BC], ctcert_bin, 0x180);

        element r, s;
        printf("Signing master hash\n");
        ninty_233_ecdsa_sign_sha256(&footer[0x00], (totalhashsize), &ctcert_bin[0x180], r, s);

        printf("Writing signature to footer\n");
        array<u8, 0x3C> signature = {};
        elem_to_os(r, &signature[0x00]);
        elem_to_os(s, &signature[0x1E]);
        memcpy(&footer[totalhashsize], signature.data(), 0x3C);

        printf("Fixing APCert issuer\n");
        memset(&footer[0x1DC + 0x80], 0, 0x40);
	//snprintf(apcert->issuer, 0x40, "%s-%s", ctcert->issuer, ctcert->key_id);
        snprintf((char*)&footer[0x1DC + 0x80], 0x40, "%s-%s", &footer[totalhashsize + 0x1BC + 0x80], &footer[totalhashsize + 0x1BC + 0xC0]);

        element r2, s2;
        printf("Signing APCert issuer\n");
        ninty_233_ecdsa_sign_sha256(&footer[0x1DC + 0x80], 0x100, &ctcert_bin[0x180], r2, s2);

        //while (1) {hidScanInput(); if (hidKeysDown() & KEY_A) { break; } }

        printf("Converting elements to 0x3C u8 array\n");
        elem_to_os(r2, &signature[0x00]);
        elem_to_os(s2, &signature[0x1E]);
        printf("Writing APCert to footer\n");
        memcpy(&footer[0x1DC], signature.data(), 0x3C);

        printf("Writing public key to APcert\n");
        memcpy(&footer[0x1DC + 0x108], &ctcert_bin[0x108], 0x3C);
}
#include "../include/rc4.h"

void rc4(unsigned char* data, long data_len, unsigned char* key, long key_len, unsigned char* result) {
    unsigned char T[256];
    unsigned char S[256];
    unsigned char tmp; // to be used in swaping
    int j = 0, t= 0, i= 0;

    // initialize S & K
    for (int i = 0 ; i < 256 ; i++) {
        S[i]= i;
        T[i]= key[i % key_len];
    }

    // state permutation
    for(int i = 0 ; i < 256; i++) {
        j = (j + S[i] + T[i]) % 255;

        //swap S[i] & S[j]
        tmp = S[j];
        S[j]= S[i];
        S[i] = tmp;
    }

    j = 0; // reintializing j for reuse

    for(int x = 0 ; x < data_len ; x++) {
        i = (i +1) % 255;
        j = (j + S[i]) % 255;

        //Swap S[i] & S[j]
        tmp = S[j];
        S[j]= S[i];
        S[i] = tmp;

        t = (S[i] + S[j]) % 255;

        result[x]= data[x] ^ S[t]; // XOR generated S[t] with Byte from the plaintext / cipher and append each Encrypted/Decrypted byte to result array
    }
}
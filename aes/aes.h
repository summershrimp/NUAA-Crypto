#ifndef _AES_H_
#define _AES_H_

#ifdef _MSC_VER
 #ifndef uint8_t
typedef unsigned __int8 uint8_t;
 #endif
 #ifndef uint32_t
typedef unsigned __int32 uint32_t;
 #endif
 #ifndef uint64_t
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
 #endif
 #else
 #include <stdint.h>
#endif

uint8_t gmult(uint8_t a, uint8_t b);
int GF28_Mul(uint8_t * a, uint8_t* b, uint8_t* d);
int SubBytes(uint8_t *state);
int ShiftRows(uint8_t *state);
int MixColumns(uint8_t *state);
int RevSubBytes(uint8_t *state);
int RevShiftRows(uint8_t *state);
int RevMixColumns(uint8_t *state);
int AddRoundKey(uint8_t *state, uint8_t *key, int rnd);
void rot_word(uint8_t *w);
void sub_word(uint8_t *w);
void KeyExpansion(uint8_t *key, uint8_t *w) ;

int self_encrypt(uint8_t *in, uint8_t *out, uint8_t *w);
int self_decrypt(uint8_t *in, uint8_t *out, uint8_t *w);

int AESDecrypt(uint8_t *src, uint8_t *dst, int length, int *rength, uint8_t *key, int keylength);
int AESEncrypt(uint8_t *src, uint8_t *dst, int length, int *rength, uint8_t *key, int keylength);

#endif

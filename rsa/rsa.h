#ifndef _RSA_H_
#define _RSA_H_
void GenKey(int *n, int *e, int *d);
void RSADecrypt(int *src, char* dst, int slen, int d, int n);
void RSAEncrypt(char *src, int* dst, int *dlen, int e, int n);
int pow_mod(int m, int k, int n);
#endif

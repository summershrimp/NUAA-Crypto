#ifndef _AFFINE_H_
#define _AFFINE_H_

int StatWords(char in[], int count, int out[], int *wcount);
int AffineEncrypt(char in[], unsigned int count, char out[], int key1, int key2);
int AffineDecrypt(char in[], unsigned int count, char out[], int key1, int key2);

#endif
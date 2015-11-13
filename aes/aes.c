#include <stdio.h>
#include <stdlib.h>
#include "aes.h"


char gmult(char a, char b) {

    char p = 0, i = 0, hbs = 0;

    for (i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }

        hbs = a & 0x80;
        a <<= 1;
        if (hbs) a ^= 0x1b; // 0000 0001 0001 1011  
        b >>= 1;
    }

    return (char)p;
}

void GF28_add(char a[], char b[], char d[]) {

	d[0] = a[0]^b[0];
	d[1] = a[1]^b[1];
	d[2] = a[2]^b[2];
	d[3] = a[3]^b[3];
}

int GF28_Mul(char * a, char* b, char* d)
{
    d[0] = gmult(a[0],b[0])^gmult(a[3],b[1])^gmult(a[2],b[2])^gmult(a[1],b[3]);
    d[1] = gmult(a[1],b[0])^gmult(a[0],b[1])^gmult(a[3],b[2])^gmult(a[2],b[3]);
    d[2] = gmult(a[2],b[0])^gmult(a[1],b[1])^gmult(a[0],b[2])^gmult(a[3],b[3]);
    d[3] = gmult(a[3],b[0])^gmult(a[2],b[1])^gmult(a[1],b[2])^gmult(a[0],b[3]);
    return 0;
}

char R[] = {0x02, 0x00, 0x00, 0x00};
 
char * Rcon(char i) {
	
	if (i == 1) {
		R[0] = 0x01; // x^(1-1) = x^0 = 1
	} else if (i > 1) {
		R[0] = 0x02;
		i--;
		while (i-1 > 0) {
			R[0] = gmult(R[0], 0x02);
			i--;
		}
	}
	
	return R;
}

int SubBytes(char *state)
{
    int i = 0, j = 0, t;
    for(; i<4; ++i)
    {
        for(; j<Nb; ++j)
        {
            t = state[i*Nb + j];
            state[i*Nb + j] = SBOX[t&0xf0>>4][t&0x0f];
        }
    }
    return 0;
}

int ShiftRows(char *state)
{
    int i = 1, j = 0, k, t;
    for(; i<4; ++i)
    {
        for(j = 0; j <i ; ++j)
        {
            t = state[i * Nb + 0];
            for(k=1; k<Nb; ++k)
            {
                state[i*Nb + k-1] = state[i*Nb + k];
            }
            state[i*Nb + Nb-1] = t;
        }
    }
    return 0;
}

int MixColumns(char *state)
{
    int i,j=0;
    char a[] = {0x02, 0x01, 0x01, 0x03}; // a(x) = {02} + {01}x + {01}x2 + {03}x3
    char col[4], res[4];

    for (;j<Nb;j++)
    {
        for(i=0;i<4;++i)
        {
            col[i] = state[i*Nb+j];
        }

        GF28_Mul(a, col, res);
        for(i=0; i<4; ++i)
        {
            state[i*Nb+j] = res[i];
        }
    }
    return 0;
}

int AddRoundKey(char *state, char *key, int rnd)
{
    char c;
    
    for (c = 0; c < Nb; c++) {
        state[Nb*0+c] = state[Nb*0+c]^key[4*Nb*rnd+Nb*c+0];
        state[Nb*1+c] = state[Nb*1+c]^key[4*Nb*rnd+Nb*c+1];
        state[Nb*2+c] = state[Nb*2+c]^key[4*Nb*rnd+Nb*c+2];
        state[Nb*3+c] = state[Nb*3+c]^key[4*Nb*rnd+Nb*c+3]; 
    }
    return 0;
}

void rot_word(char *w) {

    char tmp;
    int i;

    tmp = w[0];

    for (i = 0; i < 3; i++) {
        w[i] = w[i+1];
    }

    w[3] = tmp;
}

void sub_word(char *w) {

    int i;

    for (i = 0; i < 4; i++) {
        w[i] = SBOX[((w[i] & 0xf0) >> 4) ][(w[i] & 0x0f)];
    }
}

void KeyExpansion(char *key, char *w) {

    char tmp[4];
    char i;
    char len = Nb*(Nr+1);

    for (i = 0; i < Nk; i++) {
        w[4*i+0] = key[4*i+0];
        w[4*i+1] = key[4*i+1];
        w[4*i+2] = key[4*i+2];
        w[4*i+3] = key[4*i+3];
    }

    for (i = Nk; i < len; i++) {
        tmp[0] = w[4*(i-1)+0];
        tmp[1] = w[4*(i-1)+1];
        tmp[2] = w[4*(i-1)+2];
        tmp[3] = w[4*(i-1)+3];

        if (i%Nk == 0) {

            rot_word(tmp);
            sub_word(tmp);
            GF28_add(tmp, Rcon(i/Nk), tmp);

        } else if (Nk > 6 && i%Nk == 4) {

            sub_word(tmp);

        }

        w[4*i+0] = w[4*(i-Nk)+0]^tmp[0];
        w[4*i+1] = w[4*(i-Nk)+1]^tmp[1];
        w[4*i+2] = w[4*(i-Nk)+2]^tmp[2];
        w[4*i+3] = w[4*(i-Nk)+3]^tmp[3];
    }
}
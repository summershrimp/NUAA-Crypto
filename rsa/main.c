#include "rsa.h"

#include <stdio.h>

char *words="I LOVE NANJING UNIVERSITY OF AERONAUTICS AND ASTRONAUTICS";
int sec[100];
int secCount;
char dec[100];
int main(int argc, char **argv)
{
	int i;
	int n, e, d;
	int ans=pow_mod(7, 563, 561);
	printf("7^563 mod 561 = %d\n", ans);

	GenKey(&n, &e, &d);
	printf("n: %d\nPubkey: %d\nPrivKey %d\n",n ,e ,d);

	RSAEncrypt(words, sec, &secCount, e, n);
	printf("Encrypted data: \n");
	for(i=0; i<secCount; ++i)
	{
		printf("0x%x\t", sec[i]);
		if((i+1)%10 == 0)
			printf("\n");
	}

	RSADecrypt(sec, dec, secCount, d, n);
	printf("\nDecrypted data: \n");
	printf("%s", dec);


	return 0;
}
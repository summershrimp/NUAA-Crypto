#include "affine.h"

unsigned char prime[26] = 
{
	0, 0, 1, 1, 0,
	1, 0, 1, 0, 0,
	0, 1, 0, 1, 0,
	0, 0, 1, 0, 1,
	0, 0, 0, 1, 0,
	0
};

int StatWords(char in[], int count, float out[])
{
	int i,cw=0,t;
	int cc[26] = {0};
	for (i=0; i<count; ++i)
	{
		t=in[i];
		if(t >= 'A' && t <= 'Z')
		{
			t -= 'A';
			++cw;
			++cc[t];
		}
		else if (t >= 'a' && t <= 'z')
		{
			t -= 'a';
			++cw;
			++cc[t];
		}
	}
	for(i=0; i<26; ++i)
	{
		out[i] = ((float) cc[i] )/(float)cw;
	}
	return 0;
}

int rev_key(int a, int n)
{
	int p=a, q=n, t;
	int x=0, y=1, z = q/p;
	while (p != 1 && q != 1)
	{
		t = p; p = q%p; q = t;
		t = y; y = x-y*z; x = t;
		z = q/p;
	}
	y = y%n;
	if(y<0)
	{
		y += n;
	}
	return y;
}

int CalcEncKey(int ksrc1, int ksrc2, int *kdst1, int*kdst2)
{
	if(ksrc1 == 0 || ksrc2 == 0)
	{
		return 1;
	}

	int t = ksrc2 % 26;

	(*kdst1) = ksrc1 % 26;
	
	if (!prime[t])
	{
		return -1;
	}
	(*kdst2) = t;
	return 0;
}

int CalcDecKey(int ksrc1, int ksrc2, int *kdst1, int*kdst2)
{
	if(ksrc1 == 0 || ksrc2 == 0)
	{
		return 1;
	}

	int t = ksrc2 % 26;

	(*kdst1) = ksrc1 % 26;
	
	if (!prime[t])
	{
		return -1;
	}
	(*kdst2) = rev_key(t, 26);
	return 0;
}

char enc(char in, int k1, int k2)
{
	if(in >= 'A' && in <= 'Z')
	{
		in-='A';
		in = (k1+in*k2)%26;
		return in + 'A';
	}
	else if (in >= 'a' && in <= 'z')
	{
		in-='a';
		in = (k1+in*k2)%26;
		return in + 'a';
	}
	return -1;
}

char dec(char in, int k1, int k2)
{
	if(in >= 'A' && in <= 'Z')
	{
		in-='A';
		in = (k2*(in - k1))%26;
		if (in <0)
		{
			in += 26;
		}
		return in + 'A';
	}
	else if (in >= 'a' && in <= 'z')
	{
		in-='a';
		in = (k2*(in - k1))%26;
		if (in <0)
		{
			in += 26;
		}
		return in + 'a';
	}
	return -1;
}

int AffineEncrypt(char in[], unsigned int count, char out[], int key1, int key2)
{
	int i, sk1, sk2;
	i = CalcEncKey(key1, key2, &sk1, &sk2);
	if (i == -1)
	{
		return -1;
	}

	for(i=0; i<count; i++)
	{
		out[i] = enc(in[i], sk1, sk2);
		if(out[i] == -1)
			return -1;
	}

	return 0;
}

int AffineDecrypt(char in[], unsigned int count, char out[], int key1, int key2)
{
	int i, sk1, sk2;
	i = CalcDecKey(key1, key2, &sk1, &sk2);
	if (i == -1)
	{
		return -1;
	}

	for(i=0; i<count; i++)
	{
		out[i] = dec(in[i], sk1, sk2);
		if(out[i] == -1)
			return -1;
	}

	return 0;
}
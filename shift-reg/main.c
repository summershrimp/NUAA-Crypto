#include <stdio.h>
#include <stdlib.h>



int key_gen(int x1, int x2, int x3, int x4, int x5)
{
	int ret = (x1<<4) + (x2<<3) + (x3 << 2) + (x4 <<1) + x5;
	int i=5;
	while(i < 31)
	{
		ret <<= 1;
		ret += (ret>>2 & 1 ) ^ (ret >> 5 & 1);
		++i;
	}
	return ret;
}

int Encrypt(int src[], int dst[], int n, int key)
{
	int i=0;
	while(i++ < n)
	{
		dst[i] = src[i]^key;
	}
	return n;
}

int Decrypt(int src[], int dst[], int n, int key)
{
	Encrypt(src, dst, n, key);
}

int main(int argc, char *argv[])
{
	int i, ch;
	int encrypt=0, decrypt=0;
	char *filename = NULL, *password = NULL;
	int buf[1024], out[1024], key;
	char outname[256];
	FILE *fin, *fout;

	int in_length, in_count, out_count, real_out;

    for(i=1;i<argc;i++)
    {
        if(!strcmp(argv[i],"-c"))
        {
            encrypt = 1;
            continue;
        }
        if(!strcmp(argv[i],"-x"))
        {
            decrypt = 1;
            continue;
        }
    }

	for(i=1;i<argc;i++)
	{
		if(argv[i][0]!='-')
		{
			filename = argv[i];
			break;
		}
	}
    i++;
    for(;i<argc;i++)
	{
		if(argv[i][0]!='-')
		{
			password = argv[i];
			break;
		}
	}
	if (!filename || ! password)
	{
		printf ("Usage: %s [args] filename password\n",argv[0]);
		return 1;
	}
	if(strlen(password) != 5)
	{
		printf ("password must only contains 1 and 0, length must be 5!\n");
		return 1;
	}
	else 
	{
		for(i=0; i<5; ++i)
		{
			password[i] = password[i] - '0';

			if(password[i] != 1 && password[i] != 0)
			{
				break;
			}
		}
		if (i != 5)
		{
			printf ("password must only contains 1 and 0! length must be 5(%d).\n",i);
			return 1;
		}
	}
	if(!encrypt^decrypt)
	{
		printf("%s: Must specify one of -c, -x\n", argv[0]);
		return 1;
	}
	
	strcpy(outname, filename);
	strcat(outname, ".out");
    fin = fopen(filename, "rb");
    fout = fopen(outname, "wb+");
    if(!fin || !fout)
    {
    	printf("File read error !");
    	return 1;
    }
    key = key_gen(password[0],password[1],password[2],password[3],password[4]);
    printf("Generated Key is: 0x%x\n", key);
    if(encrypt)
    {
    	in_length = 0;
    	while(in_count = fread(buf + in_length, 4, 100, fin))
    	{
    		in_length += in_count;
    	}
    	Encrypt(buf, out, in_length, key);
    	out_count = fwrite(out, in_length, 4, fout);
    }
    else
    {
    	in_length = 0;
    	while(in_count = fread(buf + in_length, 4, 100, fin))
    	{
    		in_length += in_count;
    	}
    	Decrypt(buf, out, in_length, key);
    	real_out = 0;
    	out_count = fwrite(out, 4, in_length, fout);
    }
    fclose(fin);
    fclose(fout);

}
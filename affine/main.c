#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "affine.h"

int main(int argc, char *argv[])
{
	int i, ch;
	int encrypt=0, decrypt=0, stat=0;
	char *filename = NULL, *skey1 = NULL, *skey2 = NULL;
	int key1 = -1, key2 = -1;
	uint8_t buf[1024], out[1024];
	char outname[256];
	uint8_t hash[32];
	sha256_context ctx;
	FILE *fin, *fout;

	int in_count, out_count, real_out;

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
        if(!strcmp(argv[i],"--stat"))
        {
            stat = 1;
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
			skey1 = argv[i];
			sscanf(skey1, "%d", &key1);
			break;
		}
	}
	i++;
    for(;i<argc;i++)
	{
		if(argv[i][0]!='-')
		{
			skey2 = argv[i];
			sscanf(skey2, "%d", &key1);
			break;
		}
	}
	if (!filename || key 1<= 0 || key2 <= 0)
	{
		printf ("Usage: %s [args] filename key1 key2 [--stat]\nkey1, key2 must be number\nkey2 must be prime after mod 26",argv[0]);
		return 1;
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
    if(encrypt)
    {
    	while(in_count = fread(buf, 1, 512, fin))
    	{
    		if(AffineEncrypt(buf, in_count, out, key1, key2))
    		{
    			printf("encrypt error!\n");
    			return 1;
    		}

    		real_out = fwrite(out, 1, in_count, fout);
    		if(real_out != in_count)
    		{
    			printf("file output error!\n");
    			return 1;
    		}
    	}
    }
    else
    {
    	while(in_count = fread(buf, 1, 512, fin))
    	{
    		if(AESDecrypt(buf, in_count, out, key1, key2)
    		{
    			printf("decrypt error!\n");
    			return 1;
    		}
    		real_out = fwrite(out, 1, in_count, fout);
    		if(real_out != in_count)
    		{
    			printf("file output error!\n");
    			return 1;
    		}
    	}
    }
    FILE *fraw, *fenc;
    float statraw[26] = {0.0}, statenc[26] = {0.0};
    if(stat)
    {
    	if(encrypt)
    	{
    		fraw = fin;
    		fenc = fout;
    	}
    	else
    	{
    		fraw = fout;
    		fenc = fin;
    	}
    	fseek(fraw, 0, SEEK_SET)
   		fseek(fenc, 0, SEEK_SET)
    	while(in_count = fread(buf, 1, 512, fraw))
    	{
    		
    	}
    }

    fclose(fin);
    fclose(fout);



}

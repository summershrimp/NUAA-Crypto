#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "sha256.h"

int main(int argc, char *argv[])
{
	int i, ch;
	int encrypt=0, decrypt=0;
	char *filename = NULL, *password = NULL;
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
	if(!encrypt^decrypt)
	{
		printf("%s: Must specify one of -c, -x\n", argv[0]);
		return 1;
	}
	
	strcpy(outname, filename);
	strcat(outname, ".out");
	sha256_init(&ctx);
    sha256_hash(&ctx, (uint8_t *)password, (uint32_t)strlen(password));
    sha256_done(&ctx, hash);

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
    		if(AESEncrypt(buf, out, in_count, &out_count, hash, 32))
    		{
    			printf("encrypt error!\n");
    			return 1;
    		}
    		real_out = fwrite(out, 1, out_count, fout);
    		if(real_out != out_count)
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
    		if(AESDecrypt(buf, out, in_count, &out_count, hash, 32))
    		{
    			printf("decrypt error!\n");
    			return 1;
    		}
    		real_out = fwrite(out, 1, out_count, fout);
    		if(real_out != out_count)
    		{
    			printf("file output error!\n");
    			return 1;
    		}
    	}
    }
    fclose(fin);
    fclose(fout);

}

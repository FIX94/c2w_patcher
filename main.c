/*
 * Copyright (C) 2017 FIX94
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <malloc.h>
#include "rijndael.h"
#include "sha1.h"

//for c2w basic verification
static uint8_t imghdr[4] = { 0xEF, 0xA2, 0x82, 0xD9 };
static uint8_t elfhdr[4] = { 0x7F, 0x45, 0x4C, 0x46 };
//patch for LT_COMPAT_MEMCTRL_STATE (toggles between 3x and 5x ppc multiplier)
static uint8_t memctrl_ori[8]   = { 0xE3, 0x82, 0x20, 0x20, 0xE5, 0x84, 0x25, 0xB0 };
static uint8_t memctrl_patch[8] = { 0xE3, 0xC2, 0x20, 0x20, 0xE5, 0x84, 0x25, 0xB0 };
//patch for LT_SYSPROT (unlocks ppc multiplier)
static uint8_t sysprot_ori[8]   = { 0xE3, 0x83, 0x30, 0x99, 0xE5, 0x81, 0x35, 0x14 };
static uint8_t sysprot_patch[8] = { 0xE3, 0x83, 0x30, 0x9D, 0xE5, 0x81, 0x35, 0x14 };

static void printerr(char *msg)
{
	puts(msg);
	puts("Press enter to exit");
	getc(stdin);
}

int main()
{
	puts("cafe2wii Patcher v1.0 by FIX94");
	//first get the ancast key thats required
	FILE *f = fopen("starbuck_key.txt","rb");
	if(!f)
	{
		printerr("Unable to open starbuck_key.txt!");
		return -1;
	}
	fseek(f,0,SEEK_END);
	size_t fsize = ftell(f);
	if(fsize < (0x10<<1))
	{
		fclose(f);
		printerr("Key seems to be too small!");
		return -2;
	}
	rewind(f);
	char *buf = malloc(fsize);
	fread(buf,1,fsize,f);
	fclose(f);
	//parse string buffer to hex buffer
	uint8_t key[0x10];
	int i;
	for(i = 0; i < 0x10; i++)
		sscanf(buf+(i<<1),"%02x",(uint32_t*)&key[i]);
	puts("Read in key");
	free(buf);
	f = fopen("c2w.img","rb");
	if(!f)
	{
		printerr("Unable to open c2w.img!");
		return -3;
	}
	fseek(f,0,SEEK_END);
	fsize = ftell(f);
	rewind(f);
	uint8_t *encbuf = malloc(fsize);
	fread(encbuf,1,fsize,f);
	fclose(f);
	puts("Read in c2w.img");
	if(memcmp(encbuf,imghdr,4) != 0)
	{
		free(encbuf);
		printerr("Invalid c2w.img header!");
		return -4;
	}
	//open up decrypted buffer
	uint8_t *decbuf = malloc(fsize);
	memcpy(decbuf,encbuf,0x200);
	uint8_t iv[0x10];
	//technically this has IV but its not needed for our patches
	aes_set_key(key);
	memset(iv,0,0x10);
	aes_decrypt(iv,encbuf+0x200,decbuf+0x200,fsize-0x200);
	if(memcmp(decbuf+0x804,elfhdr,4) != 0)
	{
		free(encbuf);
		free(decbuf);
		printerr("c2w.img does not appear to be decrypted! Please verify your key.");
		return -5;
	}
	//apply c2w patches
	uint8_t p = 0;
	uint8_t cnt = 0;
	for(i = 0x200; i < fsize; i += 4)
	{
		if(memcmp(decbuf+i,memctrl_ori,sizeof(memctrl_ori)) == 0)
		{
			printf("Patched LT_COMPAT_MEMCTRL_STATE at %x\n", i);
			memcpy(decbuf+i,memctrl_patch,sizeof(memctrl_patch));
			cnt++; p|=1;
		}
		else if(memcmp(decbuf+i,sysprot_ori,sizeof(sysprot_ori)) == 0)
		{
			printf("Patched LT_SYSPROT at %x\n", i);
			memcpy(decbuf+i,sysprot_patch,sizeof(sysprot_patch));
			cnt++; p|=2;
		}
	}
	if(cnt != 2 || p != 3)
		puts("WARNING: Did not apply c2w.img patches as expected!");
	//technically this has IV but its not needed for our patches
	aes_set_key(key);
	memset(iv,0,0x10);
	//re-encrypt the patched buffer
	aes_encrypt(iv,decbuf+0x200,encbuf+0x200,fsize-0x200);
	//calculate sha1 of encrypted file
	SHA1Context ctx;
	SHA1Reset(&ctx);
	SHA1Input(&ctx,encbuf+0x200,fsize-0x200);
	SHA1Result(&ctx);
	//put sha1 into img
	int j;
	for(i = 0; i < 5; i++)
		for(j = 0; j < 4; j++)
			encbuf[0x1B0+(i<<2)+j] = ctx.Message_Digest[i]>>(24-(j<<3));
	//write new patched file
	f = fopen("c2p.img","wb");
	if(!f)
	{
		free(encbuf);
		free(decbuf);
		printerr("Unable to write output to c2p.img!");
		return -6;
	}
	fwrite(encbuf,1,fsize,f);
	fclose(f);
	puts("All Done!");
	puts("Press enter to exit");
	getc(stdin);
	return 0;
}

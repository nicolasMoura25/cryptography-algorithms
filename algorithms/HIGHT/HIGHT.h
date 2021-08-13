#pragma once

#include <stdio.h>

typedef struct
{
	unsigned __int8 whiteningKeys[8];
	unsigned __int8 subkeys[128];
} HightContext;

void HIGHT_init(HightContext* context, unsigned __int8* key);
void HIGHT_encrypt(HightContext* context, unsigned __int8* block, unsigned __int8* out);
void HIGHT_decrypt(HightContext* context, unsigned __int8* block, unsigned __int8* out);

void HIGHT_main(void);
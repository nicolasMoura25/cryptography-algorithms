#pragma once

#include <stdio.h>

typedef struct
{
	unsigned __int8 nrSubkeys;
	unsigned __int64 subkeys[72];
} SimonContext;

void SIMON_init(SimonContext* context, unsigned __int64* key, unsigned __int16 keyLen);
void SIMON_encrypt(SimonContext* context, unsigned __int64* block, unsigned __int64* out);
void SIMON_decrypt(SimonContext* context, unsigned __int64* block, unsigned __int64* out);

void SIMON_main(void);
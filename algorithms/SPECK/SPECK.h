#pragma once

#include <stdio.h>

typedef struct
{
	unsigned __int8 nrSubkeys;
	unsigned __int64 subkeys[34];
} SpeckContext;

void SPECK_init(SpeckContext* context, unsigned __int64* key, unsigned __int16 keyLen);
void SPECK_encrypt(SpeckContext* context, unsigned __int64* block, unsigned __int64* out);
void SPECK_decrypt(SpeckContext* context, unsigned __int64* block, unsigned __int64* out);

void SPECK_main(void);
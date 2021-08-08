#pragma once

#include <stdio.h>
#include <assert.h>

typedef struct
{
	unsigned __int16 feistelIterations;
	unsigned __int8 nrSubkeys;
	unsigned __int64 k[34];
} CamelliaContext;

void CAMELLIA_init(CamelliaContext* context, const unsigned __int64* key, unsigned __int16 keyLen);
void CAMELLIA_encrypt(const CamelliaContext* context, const unsigned __int64* block, unsigned __int64* out);
void CAMELLIA_decrypt(const CamelliaContext* context, const unsigned __int64* block, unsigned __int64* out);

void CAMELLIA_main(void);
#pragma once

#include <stdio.h>

typedef struct
{
	unsigned __int32 subkeys[32];
} SeedContext;

void SEED_init(SeedContext* context, unsigned __int32* key);
void SEED_encrypt(SeedContext* context, unsigned __int32* block, unsigned __int32* out);
void SEED_decrypt(SeedContext* context, unsigned __int32* block, unsigned __int32* out);

void SEED_main(void);
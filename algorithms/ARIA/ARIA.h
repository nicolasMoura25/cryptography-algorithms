#pragma once

#include <stdio.h>

typedef struct
{
	// each subkey is 4 parts of 32 bits
	unsigned __int32 eks[13][4];
	unsigned __int32 dks[13][4];
} AriaContext;

//TODO add 192 and 256 bit keys support
void ARIA_init(AriaContext* context, const unsigned __int32* key);
void ARIA_encrypt(AriaContext* context, unsigned __int32* block, unsigned __int32* P);
void ARIA_decrypt(AriaContext* context, unsigned __int32* block, unsigned __int32* P);

void ARIA_main(void);
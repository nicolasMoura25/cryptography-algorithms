#pragma once

#include <stdio.h>
#include <assert.h>

typedef struct
{
	unsigned __int64 roundKeys[32];
} PresentContext;

void PRESENT_init(PresentContext* context, unsigned __int16* key, unsigned __int16 keyLen);
void PRESENT_encrypt(PresentContext* context, unsigned __int16* block, unsigned __int16* out);
void PRESENT_decrypt(PresentContext* context, unsigned __int16* block, unsigned __int16* out);

void PRESENT_main(void);
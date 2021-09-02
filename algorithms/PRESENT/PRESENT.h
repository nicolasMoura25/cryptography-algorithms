#pragma once

#include <stdio.h>
#include <stdint.h>

typedef struct
{
	uint64_t roundKeys[32];
} PresentContext;

void PRESENT_init(PresentContext* context, uint16_t* key, uint16_t keyLen);
void PRESENT_encrypt(PresentContext* context, uint16_t* block, uint16_t* out);
void PRESENT_decrypt(PresentContext* context, uint16_t* block, uint16_t* out);

void PRESENT_main(void);
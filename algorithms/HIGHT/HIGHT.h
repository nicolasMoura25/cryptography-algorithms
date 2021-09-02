#pragma once

#include <stdio.h>
#include <stdint.h>

typedef struct
{
	uint8_t whiteningKeys[8];
	uint8_t subkeys[128];
} HightContext;

void HIGHT_init(HightContext* context, uint8_t* key);
void HIGHT_encrypt(HightContext* context, uint8_t* block, uint8_t* out);
void HIGHT_decrypt(HightContext* context, uint8_t* block, uint8_t* out);

void HIGHT_main(void);
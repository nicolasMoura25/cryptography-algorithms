/* HIGHT.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 13/08/2021
 *
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include "../../CTRMode.h"

typedef struct
{
	uint8_t whiteningKeys[8];
	uint8_t subkeys[128];
} HightContext;

void HIGHT_init(HightContext* context, uint8_t* key);
void HIGHT_encrypt(HightContext* context, uint8_t* block, uint8_t* out);

void HIGHT_main(CTRCounter* ctrNonce, int key_size);

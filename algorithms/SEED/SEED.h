/* SEED.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 15/08/2021
 *
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include "../../CTRMode.h"

typedef struct
{
	uint32_t subkeys[32];
} SeedContext;

void SEED_init(SeedContext* context, uint32_t* key);
void SEED_encrypt(SeedContext* context, uint32_t* block, uint32_t* out);
void SEED_decrypt(SeedContext* context, uint32_t* block, uint32_t* out);

void SEED_main(CTRCounter* ctrNonce, int key_size);
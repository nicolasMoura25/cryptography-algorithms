/* CTR.h
*
 * Author: Nicolas Moura
 * Created: 21/05/2022
 *
 */

#pragma once

#include <stdio.h>
#include <stdint.h>

typedef struct
{
	uint32_t ctrNonce[4]; 	// to 128 bits block lenth 
	uint32_t text[4];
	uint32_t cipherText[4];
	uint32_t cipherTemp[4];
	uint8_t position;	
} CTRCounter;

typedef struct
{
	uint32_t result[4];
} Block128;


enum Algorithm {ARIA_128, ARIA_192, ARIA_256, CAMELLIA_128, CAMELLIA_192, CAMELLIA_256, NOEKEON_128, SEED_128, SIMON_128, SIMON_192, SIMON_256,
SPECK_128, SPECK_192, SPECK_256,GOST };


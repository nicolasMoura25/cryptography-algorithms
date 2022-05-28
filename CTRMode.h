/* CTRMode.h
*
 * Author: Nicolas Moura
 * Created: 25/05/2022
 *
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include "CTR.h"

//void ARIA_init(AriaContext* context, const uint32_t* key, uint32_t keyLength);
//void ARIA_encrypt(AriaContext* context, uint32_t* block, uint32_t* P);
//void ARIA_decrypt(AriaContext* context, uint32_t* block, uint32_t* P);

void CTRMode_main(CTRCounter ctrCounter);
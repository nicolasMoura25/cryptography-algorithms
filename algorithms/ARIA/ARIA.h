#pragma once

#include <stdio.h>

void ARIA_encrypt(unsigned __int32* block, unsigned __int32* key, unsigned __int32* P);
void ARIA_decrypt(unsigned __int32* block, unsigned __int32* key, unsigned __int32* P);

void ARIA_main(void);
#pragma once

#include <stdio.h>
#include <assert.h>

void NOEKEON_encrypt(unsigned __int32* block, unsigned __int32* key, unsigned __int32* encryptdBlock);
void NOEKEON_decrypt(unsigned __int32* encryptedBlock, unsigned __int32* key, unsigned __int32* decryptedBlock);

void NOEKEON_main(void);
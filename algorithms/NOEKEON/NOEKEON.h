#pragma once

#include <stdio.h>
#include <stdint.h>

void NOEKEON_encrypt(uint32_t* block, uint32_t* key, uint32_t* encryptdBlock);
void NOEKEON_decrypt(uint32_t* encryptedBlock, uint32_t* key, uint32_t* decryptedBlock);

void NOEKEON_main(void);
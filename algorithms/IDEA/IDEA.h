#pragma once

#include <stdio.h>

void IDEA_encrypt(unsigned __int16* block, unsigned __int16* key, unsigned __int16* out);
void IDEA_decrypt(unsigned __int16* encryptedBlock, unsigned __int16* key, unsigned __int16* out);

void IDEA_main(void);
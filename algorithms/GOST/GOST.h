#pragma once

#include <stdio.h>

unsigned __int64 GOST_encrypt(unsigned __int64 block, unsigned __int32* key);
unsigned __int64 GOST_decrypt(unsigned __int64 encryptedBlock, unsigned __int32* key);

void GOST_main(void);
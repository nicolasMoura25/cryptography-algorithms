#pragma once

#include <stdio.h>

typedef struct
{
	unsigned __int64 encryptionKeys[52];
	unsigned __int64 decryptionKeys[52];
} IdeaContext;

void IDEA_init(IdeaContext* context, unsigned __int16* key);
void IDEA_encrypt(IdeaContext* context, unsigned __int16* block, unsigned __int16* out);
void IDEA_decrypt(IdeaContext* context, unsigned __int16* encryptedBlock, unsigned __int16* out);

void IDEA_main(void);
#pragma once

#include <stdio.h>
#include <stdint.h>

typedef struct
{
	uint16_t encryptionKeys[52];
	uint16_t decryptionKeys[52];
} IdeaContext;

void IDEA_init(IdeaContext* context, uint16_t* key);
void IDEA_encrypt(IdeaContext* context, uint16_t* block, uint16_t* out);
void IDEA_decrypt(IdeaContext* context, uint16_t* encryptedBlock, uint16_t* out);

void IDEA_main(void);
/* SPECK.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 08/08/2021
 *
 * Implementation of the SPECK block cipher with
 * 128 bits block length and 128/192/256 bits key length.
 *
 * This code follows a specification:
 *		- https://eprint.iacr.org/2013/404.pdf
 *
 * and uses other codebases as references:
 *		- https://github.com/nsacyber/simon-speck-supercop/tree/master/crypto_stream
 *
 */

#include "SPECK.h"

// Rotate Left circular shift 32 bits
static uint64_t ROL_64(uint64_t x, uint32_t n)
{
	return x << n | x >> (64 - n);
}

// Rotate Right circular shift 32 bits
static uint64_t ROR_64(uint64_t x, uint32_t n)
{
	return x >> n | x << (64 - n);
}

static void R(uint64_t* x, uint64_t* y, uint64_t k)
{
	*x = ROR_64(*x, 8);
	*x += *y;
	*x ^= k;
	*y = ROL_64(*y, 3);
	*y ^= *x;
}

static void RI(uint64_t* x, uint64_t* y, uint64_t k)
{
	*y ^= *x;
	*y = ROR_64(*y, 3);
	*x ^= k;
	*x -= *y;
	*x = ROL_64(*x, 8);
}

void SPECK_init(SpeckContext* context, uint64_t* key, uint16_t keyLen)
{
	uint64_t A;
	uint64_t B;
	uint64_t C;
	uint64_t D;
	uint64_t i;

	if (keyLen == 128)
	{
		context->nrSubkeys = 32;

		A = key[1];
		B = key[0];

		for (i = 0; i < 32; i++)
		{
			context->subkeys[i] = A;
			R(&B, &A, i);
		}
	}
	else if (keyLen == 192)
	{
		context->nrSubkeys = 33;

		A = key[2];
		B = key[1];
		C = key[0];

		for (i = 0; i < 32; i += 2)
		{
			context->subkeys[i] = A;
			R(&B, &A, i);
			context->subkeys[i + 1] = A;
			R(&C, &A, i + 1);
		}
		context->subkeys[32] = A;
	}
	else // 256
	{
		context->nrSubkeys = 34;

		A = key[3];
		B = key[2];
		C = key[1];
		D = key[0];

		for (i = 0; i < 33; i += 3)
		{
			context->subkeys[i] = A;
			R(&B, &A, i);
			context->subkeys[i + 1] = A;
			R(&C, &A, i + 1);
			context->subkeys[i + 2] = A;
			R(&D, &A, i + 2);
		}
		context->subkeys[33] = A;
	}
}

void SPECK_encrypt(SpeckContext* context, uint64_t* block, uint64_t* out)
{
	uint8_t i;
	uint64_t x = block[0];
	uint64_t y = block[1];

	for (i = 0; i < context->nrSubkeys; i++)
	{
		R(&x, &y, context->subkeys[i]);
	}

	out[0] = x;
	out[1] = y;
}

void SPECK_decrypt(SpeckContext* context, uint64_t* block, uint64_t* out)
{
	int i;
	uint64_t x = block[0];
	uint64_t y = block[1];

	for (i = context->nrSubkeys - 1; i >= 0; i--)
	{
		RI(&x, &y, context->subkeys[i]);
	}

	out[0] = x;
	out[1] = y;
}

void SPECK_main(void)
{
	SpeckContext context;
	int i;
	uint64_t key[4];
	uint64_t text[2];
	uint64_t cipherText[2];
	uint64_t expectedCipherText[2];
	uint64_t decryptedText[2];

	// test for 128-bits key

	// key 0f0e0d0c0b0a0908 0706050403020100
	key[0] = 0x0f0e0d0c0b0a0908;
	key[1] = 0x0706050403020100;

	// text 6c61766975716520 7469206564616d20
	text[0] = 0x6c61766975716520;
	text[1] = 0x7469206564616d20;

	// expected encrypted text a65d985179783265 7860fedf5c570d18
	expectedCipherText[0] = 0xa65d985179783265;
	expectedCipherText[1] = 0x7860fedf5c570d18;

	SPECK_init(&context, key, 128);

	SPECK_encrypt(&context, text, cipherText);
	SPECK_decrypt(&context, cipherText, decryptedText);

	printf("SPECK 128-bits key \n\n");

	printf("key: \t\t\t\t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", key[i]);
	}
	printf("\n");

	printf("text: \t\t\t\t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", text[i]);
	}
	printf("\n");

	printf("encrypted text: \t\t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", cipherText[i]);
	}
	printf("\n");

	printf("expected encrypted text: \t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", expectedCipherText[i]);
	}
	printf("\n");

	printf("decrypted text: \t\t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", decryptedText[i]);
	}
	printf("\n");

	// *** 192-bits key test ***

	// key 1716151413121110 0f0e0d0c0b0a0908 0706050403020100
	key[0] = 0x1716151413121110;
	key[1] = 0x0f0e0d0c0b0a0908;
	key[2] = 0x0706050403020100;

	// text 7261482066656968 43206f7420746e65
	text[0] = 0x7261482066656968;
	text[1] = 0x43206f7420746e65;

	// expected encrypted text 1be4cf3a13135566 f9bc185de03c1886
	expectedCipherText[0] = 0x1be4cf3a13135566;
	expectedCipherText[1] = 0xf9bc185de03c1886;

	SPECK_init(&context, key, 192);

	SPECK_encrypt(&context, text, cipherText);
	SPECK_decrypt(&context, cipherText, decryptedText);

	printf("\nSPECK 192-bits key \n\n");

	printf("key: \t\t\t\t");
	for (i = 0; i < 3; i++)
	{
		printf("%016llx ", key[i]);
	}
	printf("\n");

	printf("text: \t\t\t\t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", text[i]);
	}
	printf("\n");

	printf("encrypted text: \t\t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", cipherText[i]);
	}
	printf("\n");

	printf("expected encrypted text: \t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", expectedCipherText[i]);
	}
	printf("\n");

	printf("decrypted text: \t\t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", decryptedText[i]);
	}
	printf("\n");

	// *** 256-bits key test ***

	// key  1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100
	key[0] = 0x1f1e1d1c1b1a1918;
	key[1] = 0x1716151413121110;
	key[2] = 0x0f0e0d0c0b0a0908;
	key[3] = 0x0706050403020100;

	// text 65736f6874206e49 202e72656e6f6f70
	text[0] = 0x65736f6874206e49;
	text[1] = 0x202e72656e6f6f70;

	// expected encrypted text 4109010405c0f53e 4eeeb48d9c188f43
	expectedCipherText[0] = 0x4109010405c0f53e;
	expectedCipherText[1] = 0x4eeeb48d9c188f43;

	SPECK_init(&context, key, 256);

	SPECK_encrypt(&context, text, cipherText);
	SPECK_decrypt(&context, cipherText, decryptedText);

	printf("\nSPECK 256-bits key \n\n");

	printf("key: \t\t\t\t");
	for (i = 0; i < 4; i++)
	{
		printf("%016llx ", key[i]);
	}
	printf("\n");

	printf("text: \t\t\t\t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", text[i]);
	}
	printf("\n");

	printf("encrypted text: \t\t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", cipherText[i]);
	}
	printf("\n");

	printf("expected encrypted text: \t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", expectedCipherText[i]);
	}
	printf("\n");

	printf("decrypted text: \t\t");
	for (i = 0; i < 2; i++)
	{
		printf("%016llx ", decryptedText[i]);
	}
	printf("\n");
}

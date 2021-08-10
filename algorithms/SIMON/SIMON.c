#include "SIMON.h"

/*
*
*			SIMON
*
*	128-bits block 128/192/256-bits key
*
*
* This is an implementation of the cipher algorithm SIMON
*
* Implementation References:
* - https://eprint.iacr.org/2013/404.pdf
* - https://github.com/nsacyber/simon-speck-supercop/tree/master/crypto_stream
*/

// Rotate Left circular shift 32 bits
static unsigned __int64 ROL_64(unsigned __int64 x, unsigned __int32 n)
{
	return x << n | x >> (64 - n);
}

// Rotate Right circular shift 32 bits
static unsigned __int64 ROR_64(unsigned __int64 x, unsigned __int32 n)
{
	return x >> n | x << (64 - n);
}

static unsigned __int64 f(unsigned __int64 x)
{
	return (ROL_64(x, 1) & ROL_64(x, 8)) ^ ROL_64(x, 2);
}

static void R2(unsigned __int64* x, unsigned __int64* y, unsigned __int64 k, unsigned __int64 l)
{
	*y ^= f(*x);
	*y ^= k;
	*x ^= f(*y);
	*x ^= l;
}

void SIMON_init(SimonContext* context, unsigned __int64* key, unsigned __int16 keyLen)
{
	unsigned __int64 c = 0xfffffffffffffffcLL;
	unsigned __int64 z;
	unsigned __int64 i;

	if (keyLen == 128)
	{
		context->nrSubkeys = 68;

		z = 0x7369f885192c0ef5LL;

		context->subkeys[0] = key[1];
		context->subkeys[1] = key[0];

		for (i = 2; i < 66; i++)
		{
			context->subkeys[i] = c ^ (z & 1) ^ context->subkeys[i - 2] ^ ROR_64(context->subkeys[i - 1], 3) ^ ROR_64(context->subkeys[i - 1], 4);
			z >>= 1;
		}

		context->subkeys[66] = c ^ 1 ^ context->subkeys[64] ^ ROR_64(context->subkeys[65], 3) ^ ROR_64(context->subkeys[65], 4);
		context->subkeys[67] = c ^ context->subkeys[65] ^ ROR_64(context->subkeys[66], 3) ^ ROR_64(context->subkeys[66], 4);
	}
	else if (keyLen == 192)
	{
		context->nrSubkeys = 69;

		z = 0xfc2ce51207a635dbLL;

		context->subkeys[0] = key[2];
		context->subkeys[1] = key[1];
		context->subkeys[2] = key[0];

		for (i = 3; i < 67; i++)
		{
			context->subkeys[i] = c ^ (z & 1) ^ context->subkeys[i - 3] ^ ROR_64(context->subkeys[i - 1], 3) ^ ROR_64(context->subkeys[i - 1], 4);
			z >>= 1;
		}

		context->subkeys[67] = c ^ context->subkeys[64] ^ ROR_64(context->subkeys[66], 3) ^ ROR_64(context->subkeys[66], 4);
		context->subkeys[68] = c ^ 1 ^ context->subkeys[65] ^ ROR_64(context->subkeys[67], 3) ^ ROR_64(context->subkeys[67], 4);
	}
	else // 256
	{
		context->nrSubkeys = 72;

		z = 0xfdc94c3a046d678bLL;

		context->subkeys[0] = key[3];
		context->subkeys[1] = key[2];
		context->subkeys[2] = key[1];
		context->subkeys[3] = key[0];

		for (i = 4; i < 68; i++)
		{
			context->subkeys[i] = c ^ (z & 1) ^ context->subkeys[i - 4] ^ ROR_64(context->subkeys[i - 1], 3) ^ context->subkeys[i - 3] ^ ROR_64(context->subkeys[i - 1], 4) ^ ROR_64(context->subkeys[i - 3], 1);
			z >>= 1;
		}

		context->subkeys[68] = c ^ context->subkeys[64] ^ ROR_64(context->subkeys[67], 3) ^ context->subkeys[65] ^ ROR_64(context->subkeys[67], 4) ^ ROR_64(context->subkeys[65], 1);
		context->subkeys[69] = c ^ 1 ^ context->subkeys[65] ^ ROR_64(context->subkeys[68], 3) ^ context->subkeys[66] ^ ROR_64(context->subkeys[68], 4) ^ ROR_64(context->subkeys[66], 1);
		context->subkeys[70] = c ^ context->subkeys[66] ^ ROR_64(context->subkeys[69], 3) ^ context->subkeys[67] ^ ROR_64(context->subkeys[69], 4) ^ ROR_64(context->subkeys[67], 1);
		context->subkeys[71] = c ^ context->subkeys[67] ^ ROR_64(context->subkeys[70], 3) ^ context->subkeys[68] ^ ROR_64(context->subkeys[70], 4) ^ ROR_64(context->subkeys[68], 1);
	}
}

void SIMON_encrypt(SimonContext* context, unsigned __int64* block, unsigned __int64* out)
{
	unsigned __int8 i;
	unsigned __int64 x = block[0];
	unsigned __int64 y = block[1];
	unsigned __int64 t;

	if (context->nrSubkeys == 69)
	{
		for (i = 0; i < 68; i += 2)
		{
			R2(&x, &y, context->subkeys[i], context->subkeys[i + 1]);
		}

		y ^= f(x);
		y ^= context->subkeys[68];
		t = x;
		x = y;
		y = t;
	}
	else
	{
		for (i = 0; i < context->nrSubkeys; i += 2)
		{
			R2(&x, &y, context->subkeys[i], context->subkeys[i + 1]);
		}
	}

	out[0] = x;
	out[1] = y;
}

void SIMON_decrypt(SimonContext* context, unsigned __int64* block, unsigned __int64* out)
{
	int i;
	unsigned __int64 x = block[0];
	unsigned __int64 y = block[1];
	unsigned __int64 t;

	if (context->nrSubkeys == 69)
	{
		t = y;
		y = x;
		x = t;
		y ^= context->subkeys[68];
		y ^= f(x);

		for (i = 67; i >= 0; i -= 2)
		{
			R2(&y, &x, context->subkeys[i], context->subkeys[i - 1]);
		}
	}
	else
	{
		for (i = context->nrSubkeys - 1; i >= 0; i -= 2)
		{
			R2(&y, &x, context->subkeys[i], context->subkeys[i - 1]);
		}
	}

	out[0] = x;
	out[1] = y;
}

void SIMON_main(void)
{
	SimonContext context;
	int i;
	unsigned __int64 key[4];
	unsigned __int64 text[2];
	unsigned __int64 cipherText[2];
	unsigned __int64 expectedCipherText[2];
	unsigned __int64 decryptedText[2];

	// test for 128-bits key

	// key 0f0e0d0c0b0a0908 0706050403020100
	key[0] = 0x0f0e0d0c0b0a0908;
	key[1] = 0x0706050403020100;

	// text 6373656420737265 6c6c657661727420
	text[0] = 0x6373656420737265;
	text[1] = 0x6c6c657661727420;

	// expected encrypted text 49681b1e1e54fe3f 65aa832af84e0bbc
	expectedCipherText[0] = 0x49681b1e1e54fe3f;
	expectedCipherText[1] = 0x65aa832af84e0bbc;

	SIMON_init(&context, key, 128);

	SIMON_encrypt(&context, text, cipherText);
	SIMON_decrypt(&context, cipherText, decryptedText);

	printf("\nSIMON 128-bits key \n\n");

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

	// text 206572656874206e 6568772065626972
	text[0] = 0x206572656874206e;
	text[1] = 0x6568772065626972;

	// expected encrypted text c4ac61effcdc0d4f 6c9c8d6e2597b85b
	expectedCipherText[0] = 0xc4ac61effcdc0d4f;
	expectedCipherText[1] = 0x6c9c8d6e2597b85b;

	SIMON_init(&context, key, 192);

	SIMON_encrypt(&context, text, cipherText);
	SIMON_decrypt(&context, cipherText, decryptedText);

	printf("\nSIMON 192-bits key \n\n");

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

	// text 74206e69206d6f6f 6d69732061207369
	text[0] = 0x74206e69206d6f6f;
	text[1] = 0x6d69732061207369;

	// expected encrypted text 8d2b5579afc8a3a0 3bf72a87efe7b868
	expectedCipherText[0] = 0x8d2b5579afc8a3a0;
	expectedCipherText[1] = 0x3bf72a87efe7b868;

	SIMON_init(&context, key, 256);

	SIMON_encrypt(&context, text, cipherText);
	SIMON_decrypt(&context, cipherText, decryptedText);

	printf("\nSIMON 256-bits key \n\n");

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

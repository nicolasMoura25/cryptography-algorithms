#include "IDEA.h"

/*
*
* 			IDEA
*
*	64-bits block 128-bits key
*
*
* This is an implementation of the cipher algorithm IDEA
*
* Implementation References:
* - https://github.com/stamparm/cryptospecs/blob/master/symmetrical/specs/idea.pdf
* - https://github.com/stamparm/cryptospecs/blob/master/symmetrical/sources/idea.c
* - https://github.com/bgreenlee/PassKeeper/blob/master/CRYPTLIB/IDEA/IDEA.C
* - https://citeseerx.ist.psu.edu/viewdoc/download;jsessionid=B830DE37452CA41AE7336F3C1DA326AA?doi=10.1.1.14.3451&rep=rep1&type=pdf
*/

#define NR_ROUNDS 8
#define ENCRYPTION_KEY_LEN 6 * NR_ROUNDS + 4 // 52 subkeys

static unsigned __int16 mul(unsigned __int16 a, unsigned __int16 b)
{
	long p;
	unsigned long q;

	if (a == 0)
		return (unsigned __int16)(1 - b);
	else if (b == 0)
		return (unsigned __int16)(1 - a);

	q = (unsigned long)a * (unsigned long)b;
	p = (q & 65535) - (q >> 16);

	if (p <= 0)
		p++;
	return (unsigned __int16)p;
}

/*
* Euclidean multiplicative mod 65537 inverse algorithm
*/
static unsigned __int16 inv(unsigned __int16 x)
{
	unsigned __int16 t0 = 1, t1;
	unsigned __int16 q, y;

	if (x <= 1)
		return x;	// 0 and 1 are self-inverse 

	t1 = 0x10001L / x;	// Since x >= 2, this fits into 16 bits 
	y = 0x10001L % x;

	if (y == 1)
		return 1 - t1;

	do
	{
		q = x / y;
		x = x % y;
		t0 += q * t1;
		if (x == 1)
			return t0;
		q = y / x;
		y = y % x;
		t1 += q * t0;
	}
	while (y != 1);

	return 1 - t1;
}

static void generateEncryptionKeys(unsigned __int16* key, unsigned __int16 Z[52])
{
	int i;

	// copy initial values from original key
	for (i = 0; i < 8; i++)
	{
		Z[i] = key[i];
	}

	// generate remaining subkeys in shift phase
	for (; i < 52; i++)
	{
		if ((i & 7) == 6)
		{
			Z[i] = (Z[i - 7] << 9) ^ (Z[i - 14] >> 7);
		}
		else if ((i & 7) == 7)
		{
			Z[i] = (Z[i - 15] << 9) ^ (Z[i - 14] >> 7);
		}
		else
		{
			Z[i] = (Z[i - 7] << 9) ^ (Z[i - 6] >> 7);
		}
	}
}

static void generateDecryptionKeys(unsigned __int16* key, unsigned __int16 Z[52])
{
	int i;
	unsigned __int16 t1, t2, t3;
	unsigned __int16 temp[ENCRYPTION_KEY_LEN];
	unsigned __int16* p = temp + ENCRYPTION_KEY_LEN;

	t1 = inv(*key++);
	t2 = -*key++;
	t3 = -*key++;
	*--p = inv(*key++);
	*--p = t3;
	*--p = t2;
	*--p = t1;

	for (i = 0; i < NR_ROUNDS - 1; i++)
	{
		t1 = *key++;
		*--p = *key++;
		*--p = t1;

		t1 = inv(*key++);
		t2 = -*key++;
		t3 = -*key++;
		*--p = inv(*key++);
		*--p = t2;
		*--p = t3;
		*--p = t1;
	}
	t1 = *key++;
	*--p = *key++;
	*--p = t1;

	t1 = inv(*key++);
	t2 = -*key++;
	t3 = -*key++;
	*--p = inv(*key++);
	*--p = t3;
	*--p = t2;
	*--p = t1;

	/* Copy and destroy temp copy */
	memcpy(Z, temp, sizeof(temp));
}

static void idea(unsigned __int16* block, unsigned __int16* Z, unsigned __int16* out)
{
	unsigned __int16 i;
	unsigned __int16 a;
	unsigned __int16 b;
	unsigned __int16 x0 = block[0];
	unsigned __int16 x1 = block[1];
	unsigned __int16 x2 = block[2];
	unsigned __int16 x3 = block[3];

	// round phase
	for (i = 1; i <= NR_ROUNDS; i++)
	{
		// confusion / group operations
		x0 = mul(*Z++, x0);
		x1 += *Z++;
		x2 += *Z++;
		x3 = mul(*Z++, x3);

		// diffusion / MA (multiplication-addition) structure
		b = mul(*Z++, x0 ^ x2);
		a = mul(*Z++, b + (x1 ^ x3));
		b += a;

		// involuntary permutation
		x0 = a ^ x0;
		x3 = b ^ x3;
		b ^= x1;
		x1 = a ^ x2;
		x2 = b;
	}

	// output transformation
	out[0] = mul(*Z++, x0);
	out[1] = *Z++ + x2;
	out[2] = *Z++ + x1;
	out[3] = mul(*Z++, x3);
}

void IDEA_init(IdeaContext* context, unsigned __int16* key)
{
	generateEncryptionKeys(key, context->encryptionKeys);
	generateDecryptionKeys(context->encryptionKeys, context->decryptionKeys);
}

void IDEA_encrypt(IdeaContext* context, unsigned __int16* block, unsigned __int16* out)
{
	idea(block, context->encryptionKeys, out);
}

void IDEA_decrypt(IdeaContext* context, unsigned __int16* encryptedBlock, unsigned __int16* out)
{
	idea(encryptedBlock, context->decryptionKeys, out);
}

void IDEA_main(void)
{
	IdeaContext context;
	int i;
	unsigned __int16 key[8];
	unsigned __int16 text[4];
	unsigned __int16 cipherText[4];
	unsigned __int16 expectedCipherText[4];
	unsigned __int16 decryptedText[4];

	// key 12345678
	for (i = 1; i <= 8; i++)
	{
		key[i - 1] = i;
	}

	// text 0123
	for (i = 0; i < 4; i++)
	{
		text[i] = i;
	}

	// 46036071540828133
	expectedCipherText[0] = 4603;
	expectedCipherText[1] = 60715;
	expectedCipherText[2] = 408;
	expectedCipherText[3] = 28133;

	IDEA_init(&context, key);
	IDEA_encrypt(&context, text, cipherText);
	IDEA_decrypt(&context, cipherText, decryptedText);

	printf("\nIDEA \n\n");

	printf("key: \t\t\t\t");
	for (i = 0; i < 8; i++)
	{
		printf("%08x ", key[i]);
	}
	printf("\n");

	printf("text: \t\t\t\t");
	for (i = 0; i < 4; i++)
	{
		printf("%08x ", text[i]);
	}
	printf("\n");

	printf("encrypted text: \t\t");
	for (i = 0; i < 4; i++)
	{
		printf("%08x ", cipherText[i]);
	}
	printf("\n");

	printf("expected encrypted text: \t");
	for (i = 0; i < 4; i++)
	{
		printf("%08x ", expectedCipherText[i]);
	}
	printf("\n");

	printf("decrypted text: \t\t");
	for (i = 0; i < 4; i++)
	{
		printf("%08x ", decryptedText[i]);
	}
	printf("\n");
}
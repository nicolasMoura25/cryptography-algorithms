#include "NOEKEON.h"

/*
*
*			NOEKEON
*
*	128-bits block 128-bits key
*
*
* This is an implementation of the cipher algorithm NOEKEON
*
* Implementation References:
* - https://github.com/jl777/libjl777/blob/master/NXTservices/noekeon.c
* - https://github.com/stamparm/cryptospecs/blob/master/symmetrical/sources/noekeon.c
* - http://gro.noekeon.org/Noekeon-spec.pdf
* - https://github.com/cantora/avr-crypto-lib/blob/master/noekeon/noekeon.c
*/

#define NR_ROUNDS 16

static const unsigned __int32 RC[] =
{
   0x80, 0x1b, 0x36, 0x6c,
   0xd8, 0xab, 0x4d, 0x9a,
   0x2f, 0x5e, 0xbc, 0x63,
   0xc6, 0x97, 0x35, 0x6a,
   0xd4
};

static const unsigned __int32 NULL_VECTOR[] =
{
	0x00, 0x00, 0x00, 0x00
};

static void MOV_128(unsigned __int32* y, unsigned __int32* x)
{
	y[0] = x[0];
	y[1] = x[1];
	y[2] = x[2];
	y[3] = x[3];
}

// Rotate Left circular shift 32 bits
static unsigned __int32 ROL_32(unsigned __int32 x, unsigned __int32 n)
{
	return x << n | x >> (32 - n);
}

// Rotate Right circular shift 32 bits
static unsigned __int32 ROR_32(unsigned __int32 x, unsigned __int32 n)
{
	return x >> n | x << (32 - n);
}

static void pi1(unsigned __int32* a)
{
	a[1] = ROL_32(a[1], 1);
	a[2] = ROL_32(a[2], 5);
	a[3] = ROL_32(a[3], 2);
}

static void pi2(unsigned __int32* a)
{
	a[1] = ROR_32(a[1], 1);
	a[2] = ROR_32(a[2], 5);
	a[3] = ROR_32(a[3], 2);
}

static void gamma(unsigned __int32* a)
{
	unsigned __int32 tmp;

	a[1] ^= ~a[3] & ~a[2];
	a[0] ^= a[2] & a[1];

	tmp = a[3];
	a[3] = a[0];
	a[0] = tmp;

	a[2] ^= a[0] ^ a[1] ^ a[3];
	a[1] ^= ~a[3] & ~a[2];
	a[0] ^= a[2] & a[1];
}

static void theta(unsigned __int32* k, unsigned __int32* a)
{
	unsigned __int32 temp = a[0] ^ a[2];
	temp ^= ROR_32(temp, 8) ^ ROL_32(temp, 8);

	a[1] ^= temp;
	a[3] ^= temp;

	a[0] ^= k[0];
	a[1] ^= k[1];
	a[2] ^= k[2];
	a[3] ^= k[3];

	temp = a[1] ^ a[3];
	temp ^= ROR_32(temp, 8) ^ ROL_32(temp, 8);

	a[0] ^= temp;
	a[2] ^= temp;
}

static void round(unsigned __int32* key, unsigned __int32* block, unsigned __int32 c1, unsigned __int32 c2)
{
	block[0] ^= c1;
	theta(key, block);
	block[0] ^= c2;
	pi1(block);
	gamma(block);
	pi2(block);
}

void NOEKEON_encrypt(unsigned __int32* block, unsigned __int32* key, unsigned __int32* encryptdBlock)
{
	MOV_128(encryptdBlock, block);
	for (int i = 0; i < NR_ROUNDS; i++)
	{
		round(key, encryptdBlock, RC[i], 0);
	}

	encryptdBlock[0] ^= RC[NR_ROUNDS];
	theta(key, encryptdBlock);
}

void NOEKEON_decrypt(unsigned __int32* encryptedBlock, unsigned __int32* key, unsigned __int32* decryptedBlock)
{
	unsigned __int32 workingKey[4];

	MOV_128(decryptedBlock, encryptedBlock);
	MOV_128(workingKey, key);

	theta(NULL_VECTOR, workingKey);

	for (int i = NR_ROUNDS; i > 0; i--)
	{
		round(workingKey, decryptedBlock, 0, RC[i]);
	}

	theta(workingKey, decryptedBlock);
	decryptedBlock[0] ^= RC[0];
}

void NOEKEON_main(void)
{
	int i;
	unsigned __int32 key[4];
	unsigned __int32 text[4];
	unsigned __int32 cipherText[4];
	unsigned __int32 decryptedText[4];

	// key 000102030405060708090a0b0c0d0e0f
	key[0] = 0x00010203;
	key[1] = 0x04050607;
	key[2] = 0x08090a0b;
	key[3] = 0x0c0d0e0f;

	// text 00112233445566778899aabbccddeeff
	text[0] = 0x00112233;
	text[1] = 0x44556677;
	text[2] = 0x8899aabb;
	text[3] = 0xccddeeff;

	NOEKEON_encrypt(text, key, cipherText);
	NOEKEON_decrypt(cipherText, key, decryptedText);

	printf("\nNOEKEON \n\n");

	printf("key: \t\t\t\t");
	for (i = 0; i < 4; i++)
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

	printf("decrypted text: \t\t");
	for (i = 0; i < 4; i++)
	{
		printf("%08x ", decryptedText[i]);
	}
	printf("\n");
}
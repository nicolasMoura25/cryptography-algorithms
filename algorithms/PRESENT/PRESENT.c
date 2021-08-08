#include "PRESENT.h"

/*
*
*			PRESENT
*
*	64-bits block 80-bits / 128-bits key
*
*
* This is an implementation of the cipher algorithm PRESENT
*
* Implementation References:
* - https://www.iacr.org/archive/ches2007/47270450/47270450.pdf
* - https://github.com/kurtfu/present
* - https://www.oryx-embedded.com/doc/present_8c_source.html
* - https://github.com/Pepton21/present-cipher
*/

#define NR_ROUNDS 31

// s-box
const unsigned __int8 sbox[16] =
{
	0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2
};

// inverse s-box
const unsigned __int8 isbox[16] =
{
	0x5, 0xe, 0xf, 0x8, 0xc, 0x1, 0x2, 0xd, 0xb, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xa
};

// permutation table
const unsigned __int8 p[64] =
{
	0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
	4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
	8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
	12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};

void PRESENT_init(PresentContext* context, unsigned __int16* key, unsigned __int16 keyLen)
{
	unsigned __int64 keyHigh;
	unsigned __int64 keyLow;

	if (keyLen == 80) // generate subkeys for 80 bit key
	{
		keyHigh = key[0];
		keyLow = (unsigned __int64)key[1] << 48
			| (unsigned __int64)key[2] << 32
			| (unsigned __int64)key[3] << 16
			| key[4];

		// first subkey is 64 leftmost bits of the key
		context->roundKeys[0] = keyHigh << 48 | keyLow >> 16;

		for (unsigned __int8 i = 1; i <= NR_ROUNDS; i++)
		{
			//  key register is rotated by 61 bit positions to the left (cyclic left shift of 61)
			unsigned __int64 temp = keyHigh;
			keyHigh = keyLow >> 3 & 0xffff;
			keyLow = keyLow << 61 | temp << 45 | keyLow >> 19;

			// the left-most four bits are passed through the sbox
			temp = sbox[(keyHigh >> 12) & 0xf];
			keyHigh = (keyHigh & 0x0fff) | (temp << 12);

			// round_counter value i is exclusive - ored with bits k19 k18 k17 k16 k15
			keyLow ^= (unsigned __int64)i << 15;

			// save subkey with 64 leftmost bits of the key
			context->roundKeys[i] = keyHigh << 48 | keyLow >> 16;
		}
	}
	else // generate subkeys assuming key is 128 bits
	{
		keyHigh = (unsigned __int64)key[0] << 48
			| (unsigned __int64)key[1] << 32
			| (unsigned __int64)key[2] << 16
			| key[3];
		keyLow = (unsigned __int64)key[4] << 48
			| (unsigned __int64)key[5] << 32
			| (unsigned __int64)key[6] << 16
			| key[7];

		// first subkey is 64 leftmost bits of the key
		context->roundKeys[0] = keyHigh;

		for (int i = 1; i <= NR_ROUNDS; i++)
		{
			//  key register is rotated by 61 bit positions to the left (cyclic left shift of 61)
			unsigned __int64 temp = keyHigh;
			keyHigh = temp << 61 | keyLow >> 3;
			keyLow = keyLow << 61 | temp >> 3;;

			// the left-most eight bits are passed through the sbox
			temp = sbox[(keyHigh >> 60) & 0xf];
			keyHigh |= temp << 60;
			temp = sbox[(keyHigh >> 56) & 0xf];
			keyHigh |= temp << 56;

			// round_counter value i is exclusive - ored with bits k66 k65 k64 k63 k62
			keyHigh ^= i >> 2;
			keyLow ^= (unsigned __int64)i << 62;

			// save subkey with 64 leftmost bits of the key
			context->roundKeys[i] = keyHigh;
		}
	}
}

/*
	Encryption order:

	for round = 0 to 30 do
		addRoundKey(state, Ki)
		sBoxLayer(state)
		pLayer(state)
	end for

	addRoundKey(state, k31)
*/
void PRESENT_encrypt(PresentContext* context, unsigned __int16* block, unsigned __int16* out)
{
	unsigned __int8 i;
	unsigned __int8 round;
	unsigned __int64 state;
	unsigned __int64 temp;

	// copy block to state
	state = (unsigned __int64)block[0] << 48
		| (unsigned __int64)block[1] << 32
		| (unsigned __int64)block[2] << 16
		| block[3];

	for (round = 0; round < NR_ROUNDS; round++)
	{
		// add round key
		state ^= context->roundKeys[round];

		// sbox substitution layer
		// divide state into 16 parts of 4 bits and substitute these parts
		// according to the sbox
		// in this case we are dividing in 8 parts in the loop, but inside the loop
		// splitting into high and low parts
		temp = 0;
		for (i = 0; i < 8; i++)
		{
			unsigned __int8 pos = (unsigned __int8)(state >> (8 * (7 - i)));
			unsigned __int8 highNybble = sbox[(pos >> 4) & 0x0f];
			unsigned __int8 lowNybble = sbox[pos & 0x0f];

			unsigned __int64 mask = 0;
			mask |= highNybble << 4 | lowNybble;
			mask = mask << (56 - (8 * i));
			temp |= mask;
		}
		state = temp;

		// permutation layer
		// change order of all bits according to the permutation table
		temp = 0;
		for (i = 0; i < 64; i++)
		{
			unsigned __int8 distance = 63 - i;
			temp |= ((state >> distance & 0x1) << (63 - p[i]));
		}
		state = temp;
	}

	// add last round key
	state ^= context->roundKeys[round];

	// copy state to output;
	out[0] = (unsigned __int16)(state >> 48);
	out[1] = (unsigned __int16)(state >> 32);
	out[2] = (unsigned __int16)(state >> 16);
	out[3] = (unsigned __int16)state;
}

/*
	Decryption order:

	for round = 31 to 1 do
		addRoundKey(state, Ki)
		inversePLayer(state)
		inverseSBoxLayer(state)
	end for

	addRoundKey(state, k0)
*/
void PRESENT_decrypt(PresentContext* context, unsigned __int16* block, unsigned __int16* out)
{
	unsigned __int8 i;
	unsigned __int8 round;
	unsigned __int64 state;
	unsigned __int64 temp;

	// copy block to state
	state = (unsigned __int64)block[0] << 48
		| (unsigned __int64)block[1] << 32
		| (unsigned __int64)block[2] << 16
		| block[3];

	// decrypt we run from last round key to the first one
	for (round = NR_ROUNDS; round > 0; round--)
	{
		// add round key
		state ^= context->roundKeys[round];

		// permutation layer
		// change order of all bits according to the permutation table
		// but in reverse order
		temp = 0;
		for (i = 0; i < 64; i++)
		{
			unsigned __int8 distance = 63 - p[i];
			temp = (temp << 1) | ((state >> distance) & 0x1);
		}
		state = temp;

		// sbox substitution layer
		// divide state into 16 parts of 4 bits and substitute these parts
		// according to the inverse sbox
		// in this case we are dividing in 8 parts in the loop, but inside the loop
		// splitting into high and low parts
		temp = 0;
		for (i = 0; i < 8; i++)
		{
			unsigned __int8 pos = (unsigned __int8)(state >> (8 * (7 - i)));
			unsigned __int8 highNybble = isbox[(pos >> 4) & 0x0f];
			unsigned __int8 lowNybble = isbox[pos & 0x0f];

			unsigned __int64 mask = 0;
			mask |= highNybble << 4 | lowNybble;
			mask = mask << (56 - (8 * i));
			temp |= mask;
		}
		state = temp;
	}

	// add last key
	state ^= context->roundKeys[round];

	// copy state to output;
	out[0] = (unsigned __int16)(state >> 48);
	out[1] = (unsigned __int16)(state >> 32);
	out[2] = (unsigned __int16)(state >> 16);
	out[3] = (unsigned __int16)state;
}

void PRESENT_main(void)
{
	PresentContext context;
	int i;
	unsigned __int16 key[8];
	unsigned __int16 text[4];
	unsigned __int16 cipherText[4];
	unsigned __int16 expectedCipherText[4];
	unsigned __int16 decryptedText[4];

	// test for 80-bits key

	// key 00000000 00000000 0000
	key[0] = 0x0000;
	key[1] = 0x0000;
	key[2] = 0x0000;
	key[3] = 0x0000;
	key[4] = 0x0000;
	key[5] = 0x0000;
	key[6] = 0x0000;
	key[7] = 0x0000;

	// text 00000000 00000000
	text[0] = 0x0000;
	text[1] = 0x0000;
	text[2] = 0x0000;
	text[3] = 0x0000;

	// expected encryption text 5579C138 7B228445
	expectedCipherText[0] = 0x5579;
	expectedCipherText[1] = 0xc138;
	expectedCipherText[2] = 0x7b22;
	expectedCipherText[3] = 0x8445;

	// *** 80-bits key test ***

	PRESENT_init(&context, key, 80);

	PRESENT_encrypt(&context, text, cipherText);
	PRESENT_decrypt(&context, cipherText, decryptedText);

	printf("\nPRESENT 80-bits key \n\n");

	printf("key: \t\t\t\t");
	for (i = 0; i < 5; i++)
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

	// *** 128-bits key test ***

	// expected encryption text 04bdd5f4 eaefcc19
	expectedCipherText[0] = 0x04bd;
	expectedCipherText[1] = 0xd5f4;
	expectedCipherText[2] = 0xeaef;
	expectedCipherText[3] = 0xcc19;

	PRESENT_init(&context, key, 128);

	PRESENT_encrypt(&context, text, cipherText);
	PRESENT_decrypt(&context, cipherText, decryptedText);

	printf("\nPRESENT 128-bits key \n\n");

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
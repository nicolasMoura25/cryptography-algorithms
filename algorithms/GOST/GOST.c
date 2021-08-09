#include "GOST.h"

/*
*
* 			GOST
*
*	64-bits block 256-bits key
*
*
* This is an implementation of the cipher algorithm GOST 28147-89 in Electronic Codebook Mode
*
* Implementation References:
* - https://datatracker.ietf.org/doc/html/rfc5830
* - https://github.com/rbingabo/GOST-block-cipher
* -  B.Shneier, ”Applied Cryptography”, John Wiley & Sons, pp. 331-334
*		(https://mrajacse.files.wordpress.com/2012/01/applied-cryptography-2nd-ed-b-schneier.pdf pag. 277)
*/

unsigned __int32 CM1;
unsigned __int32 CM2;
unsigned __int32 N1;
unsigned __int32 N2;
unsigned __int32 R;

// S-box used by the Central Bank of Russian Federation
const unsigned __int8 s_box[8][16] = {
									{ 4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 },
									{ 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 },
									{ 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11 },
									{ 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3 },
									{ 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2 },
									{ 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14 },
									{ 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12 },
									{ 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 }
};

void round(unsigned __int32 xi)
{
	CM1 = (N1 + xi) % 4294967296; // 2^32

	// read entire s-box column according to the CM1 bits
	unsigned __int32 SN = 0;
	for (int j = 0; j <= 7; j++)
	{
		/*
		* 32 bits input is divided into 8 parts, each of 4 bits
		* to a correponding substitution point column point
		* in the s-box
		*
		* The line below generate a random column that will be
		* read from the s-box at each line and based on the
		* size of the total 16 columns of s-box (and thus % 16)
		*/
		unsigned __int8 Ni = (CM1 >> (4 * (7 - j))) % 16;
		Ni = s_box[j][Ni]; // substitution through s-blocks.

		// place the read bits to correct position in the 32 bit output
		unsigned __int32 mask = 0;
		mask = mask | Ni;
		mask = mask << (28 - (4 * j));
		SN = SN | mask;
	}

	R = SN;

	// cyclic 11 shift
	unsigned __int32 mask = R << 11;
	R = (R >> 21) | mask;

	// modulo 2 addition
	CM2 = R ^ N2;
	N2 = N1;
	N1 = CM2;
}

unsigned __int64 GOST_encrypt(unsigned __int64 block, unsigned __int32* key)
{
	N1 = (unsigned __int32)block;
	N2 = block >> 32;

	// first 24 rounds
	for (int k = 0; k < 3; k++)
	{
		for (int i = 0; i <= 7; i++)
		{
			round(key[i]);
		}
	}

	// last 8 rounds
	for (int i = 7; i >= 0; i--)
	{
		round(key[i]);
	}

	unsigned __int64 tc = N1;
	tc = (tc << 32) | N2;
	return tc;
}

unsigned __int64 GOST_decrypt(unsigned __int64 encryptedBlock, unsigned __int32* key)
{
	N1 = (unsigned __int32)encryptedBlock;
	N2 = encryptedBlock >> 32;

	// last 8 rounds
	for (int i = 0; i <= 7; i++)
	{
		round(key[i]);
	}

	// first 24 rounds
	for (int k = 0; k < 3; k++)
	{
		for (int i = 7; i >= 0; i--)
		{
			round(key[i]);
		}
	}

	unsigned __int64 tc = N1;
	tc = (tc << 32) | N2;
	return tc;
}

void GOST_main(void)
{
	unsigned __int32 key[8];
	int i;
	for (i = 0; i < 8; i++)
	{
		key[i] = i;
	}

	unsigned __int64 text = 118105110105;
	unsigned __int64 expectedCipherText = 3078704057068866123;

	unsigned __int64 cipherText = GOST_encrypt(text, key);
	unsigned __int64 decrypted = GOST_decrypt(cipherText, key);

	printf("\nGOST \n\n");

	printf("key: \t\t\t\t");
	for (i = 0; i < 8; i++)
	{
		printf("%08x ", key[i]);
	}
	printf("\n");

	printf("text: \t\t\t\t%016llx", text);
	printf("\n");

	printf("encrypted text: \t\t%016llx", cipherText);
	printf("\n");

	printf("expected encrypted text: \t%016llx", expectedCipherText);
	printf("\n");

	printf("decrypted text: \t\t%016llx", decrypted);
	printf("\n");
}
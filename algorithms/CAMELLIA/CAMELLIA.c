#include "CAMELLIA.h"

/*
*
*			CAMELLIA
*
*	128-bits block 128/192/256-bits key
*
*
* This is an implementation of the cipher algorithm CAMELLIA
*
* Implementation References:
* - https://datatracker.ietf.org/doc/html/rfc3713
* - https://www.cryptrec.go.jp/en/cryptrec_03_spec_cypherlist_files/PDF/06_01espec.pdf
* - https://info.isl.ntt.co.jp/crypt/camellia/dl/reference/sac_camellia.pdf
* - https://www.oryx-embedded.com/doc/camellia_8h_source.html
* - https://github.com/Varbin/python-camellia/blob/master/src/_camellia_build/camellia.c
*/

static const unsigned __int64 sigma[6] =
{
	0xA09E667F3BCC908B, // sigma 1
	0xB67AE8584CAA73B2, // sigma 2
	0xC6EF372FE94F82BE, // sigma 3
	0x54FF53A5F1D36F1C, // sigma 4
	0x10E527FADE682D1D, // sigma 5
	0xB05688C2B3E6C1FD  // sigma 6
};

static const unsigned __int8 sbox1[256] =
{
	0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5, 0xE4, 0x85, 0x57, 0x35, 0xEA, 0x0C, 0xAE, 0x41,
	0x23, 0xEF, 0x6B, 0x93, 0x45, 0x19, 0xA5, 0x21, 0xED, 0x0E, 0x4F, 0x4E, 0x1D, 0x65, 0x92, 0xBD,
	0x86, 0xB8, 0xAF, 0x8F, 0x7C, 0xEB, 0x1F, 0xCE, 0x3E, 0x30, 0xDC, 0x5F, 0x5E, 0xC5, 0x0B, 0x1A,
	0xA6, 0xE1, 0x39, 0xCA, 0xD5, 0x47, 0x5D, 0x3D, 0xD9, 0x01, 0x5A, 0xD6, 0x51, 0x56, 0x6C, 0x4D,
	0x8B, 0x0D, 0x9A, 0x66, 0xFB, 0xCC, 0xB0, 0x2D, 0x74, 0x12, 0x2B, 0x20, 0xF0, 0xB1, 0x84, 0x99,
	0xDF, 0x4C, 0xCB, 0xC2, 0x34, 0x7E, 0x76, 0x05, 0x6D, 0xB7, 0xA9, 0x31, 0xD1, 0x17, 0x04, 0xD7,
	0x14, 0x58, 0x3A, 0x61, 0xDE, 0x1B, 0x11, 0x1C, 0x32, 0x0F, 0x9C, 0x16, 0x53, 0x18, 0xF2, 0x22,
	0xFE, 0x44, 0xCF, 0xB2, 0xC3, 0xB5, 0x7A, 0x91, 0x24, 0x08, 0xE8, 0xA8, 0x60, 0xFC, 0x69, 0x50,
	0xAA, 0xD0, 0xA0, 0x7D, 0xA1, 0x89, 0x62, 0x97, 0x54, 0x5B, 0x1E, 0x95, 0xE0, 0xFF, 0x64, 0xD2,
	0x10, 0xC4, 0x00, 0x48, 0xA3, 0xF7, 0x75, 0xDB, 0x8A, 0x03, 0xE6, 0xDA, 0x09, 0x3F, 0xDD, 0x94,
	0x87, 0x5C, 0x83, 0x02, 0xCD, 0x4A, 0x90, 0x33, 0x73, 0x67, 0xF6, 0xF3, 0x9D, 0x7F, 0xBF, 0xE2,
	0x52, 0x9B, 0xD8, 0x26, 0xC8, 0x37, 0xC6, 0x3B, 0x81, 0x96, 0x6F, 0x4B, 0x13, 0xBE, 0x63, 0x2E,
	0xE9, 0x79, 0xA7, 0x8C, 0x9F, 0x6E, 0xBC, 0x8E, 0x29, 0xF5, 0xF9, 0xB6, 0x2F, 0xFD, 0xB4, 0x59,
	0x78, 0x98, 0x06, 0x6A, 0xE7, 0x46, 0x71, 0xBA, 0xD4, 0x25, 0xAB, 0x42, 0x88, 0xA2, 0x8D, 0xFA,
	0x72, 0x07, 0xB9, 0x55, 0xF8, 0xEE, 0xAC, 0x0A, 0x36, 0x49, 0x2A, 0x68, 0x3C, 0x38, 0xF1, 0xA4,
	0x40, 0x28, 0xD3, 0x7B, 0xBB, 0xC9, 0x43, 0xC1, 0x15, 0xE3, 0xAD, 0xF4, 0x77, 0xC7, 0x80, 0x9E
};

//Substitution table 2
static const unsigned __int8 sbox2[256] =
{
   0xE0, 0x05, 0x58, 0xD9, 0x67, 0x4E, 0x81, 0xCB, 0xC9, 0x0B, 0xAE, 0x6A, 0xD5, 0x18, 0x5D, 0x82,
   0x46, 0xDF, 0xD6, 0x27, 0x8A, 0x32, 0x4B, 0x42, 0xDB, 0x1C, 0x9E, 0x9C, 0x3A, 0xCA, 0x25, 0x7B,
   0x0D, 0x71, 0x5F, 0x1F, 0xF8, 0xD7, 0x3E, 0x9D, 0x7C, 0x60, 0xB9, 0xBE, 0xBC, 0x8B, 0x16, 0x34,
   0x4D, 0xC3, 0x72, 0x95, 0xAB, 0x8E, 0xBA, 0x7A, 0xB3, 0x02, 0xB4, 0xAD, 0xA2, 0xAC, 0xD8, 0x9A,
   0x17, 0x1A, 0x35, 0xCC, 0xF7, 0x99, 0x61, 0x5A, 0xE8, 0x24, 0x56, 0x40, 0xE1, 0x63, 0x09, 0x33,
   0xBF, 0x98, 0x97, 0x85, 0x68, 0xFC, 0xEC, 0x0A, 0xDA, 0x6F, 0x53, 0x62, 0xA3, 0x2E, 0x08, 0xAF,
   0x28, 0xB0, 0x74, 0xC2, 0xBD, 0x36, 0x22, 0x38, 0x64, 0x1E, 0x39, 0x2C, 0xA6, 0x30, 0xE5, 0x44,
   0xFD, 0x88, 0x9F, 0x65, 0x87, 0x6B, 0xF4, 0x23, 0x48, 0x10, 0xD1, 0x51, 0xC0, 0xF9, 0xD2, 0xA0,
   0x55, 0xA1, 0x41, 0xFA, 0x43, 0x13, 0xC4, 0x2F, 0xA8, 0xB6, 0x3C, 0x2B, 0xC1, 0xFF, 0xC8, 0xA5,
   0x20, 0x89, 0x00, 0x90, 0x47, 0xEF, 0xEA, 0xB7, 0x15, 0x06, 0xCD, 0xB5, 0x12, 0x7E, 0xBB, 0x29,
   0x0F, 0xB8, 0x07, 0x04, 0x9B, 0x94, 0x21, 0x66, 0xE6, 0xCE, 0xED, 0xE7, 0x3B, 0xFE, 0x7F, 0xC5,
   0xA4, 0x37, 0xB1, 0x4C, 0x91, 0x6E, 0x8D, 0x76, 0x03, 0x2D, 0xDE, 0x96, 0x26, 0x7D, 0xC6, 0x5C,
   0xD3, 0xF2, 0x4F, 0x19, 0x3F, 0xDC, 0x79, 0x1D, 0x52, 0xEB, 0xF3, 0x6D, 0x5E, 0xFB, 0x69, 0xB2,
   0xF0, 0x31, 0x0C, 0xD4, 0xCF, 0x8C, 0xE2, 0x75, 0xA9, 0x4A, 0x57, 0x84, 0x11, 0x45, 0x1B, 0xF5,
   0xE4, 0x0E, 0x73, 0xAA, 0xF1, 0xDD, 0x59, 0x14, 0x6C, 0x92, 0x54, 0xD0, 0x78, 0x70, 0xE3, 0x49,
   0x80, 0x50, 0xA7, 0xF6, 0x77, 0x93, 0x86, 0x83, 0x2A, 0xC7, 0x5B, 0xE9, 0xEE, 0x8F, 0x01, 0x3D
};

//Substitution table 3
static const unsigned __int8 sbox3[256] =
{
   0x38, 0x41, 0x16, 0x76, 0xD9, 0x93, 0x60, 0xF2, 0x72, 0xC2, 0xAB, 0x9A, 0x75, 0x06, 0x57, 0xA0,
   0x91, 0xF7, 0xB5, 0xC9, 0xA2, 0x8C, 0xD2, 0x90, 0xF6, 0x07, 0xA7, 0x27, 0x8E, 0xB2, 0x49, 0xDE,
   0x43, 0x5C, 0xD7, 0xC7, 0x3E, 0xF5, 0x8F, 0x67, 0x1F, 0x18, 0x6E, 0xAF, 0x2F, 0xE2, 0x85, 0x0D,
   0x53, 0xF0, 0x9C, 0x65, 0xEA, 0xA3, 0xAE, 0x9E, 0xEC, 0x80, 0x2D, 0x6B, 0xA8, 0x2B, 0x36, 0xA6,
   0xC5, 0x86, 0x4D, 0x33, 0xFD, 0x66, 0x58, 0x96, 0x3A, 0x09, 0x95, 0x10, 0x78, 0xD8, 0x42, 0xCC,
   0xEF, 0x26, 0xE5, 0x61, 0x1A, 0x3F, 0x3B, 0x82, 0xB6, 0xDB, 0xD4, 0x98, 0xE8, 0x8B, 0x02, 0xEB,
   0x0A, 0x2C, 0x1D, 0xB0, 0x6F, 0x8D, 0x88, 0x0E, 0x19, 0x87, 0x4E, 0x0B, 0xA9, 0x0C, 0x79, 0x11,
   0x7F, 0x22, 0xE7, 0x59, 0xE1, 0xDA, 0x3D, 0xC8, 0x12, 0x04, 0x74, 0x54, 0x30, 0x7E, 0xB4, 0x28,
   0x55, 0x68, 0x50, 0xBE, 0xD0, 0xC4, 0x31, 0xCB, 0x2A, 0xAD, 0x0F, 0xCA, 0x70, 0xFF, 0x32, 0x69,
   0x08, 0x62, 0x00, 0x24, 0xD1, 0xFB, 0xBA, 0xED, 0x45, 0x81, 0x73, 0x6D, 0x84, 0x9F, 0xEE, 0x4A,
   0xC3, 0x2E, 0xC1, 0x01, 0xE6, 0x25, 0x48, 0x99, 0xB9, 0xB3, 0x7B, 0xF9, 0xCE, 0xBF, 0xDF, 0x71,
   0x29, 0xCD, 0x6C, 0x13, 0x64, 0x9B, 0x63, 0x9D, 0xC0, 0x4B, 0xB7, 0xA5, 0x89, 0x5F, 0xB1, 0x17,
   0xF4, 0xBC, 0xD3, 0x46, 0xCF, 0x37, 0x5E, 0x47, 0x94, 0xFA, 0xFC, 0x5B, 0x97, 0xFE, 0x5A, 0xAC,
   0x3C, 0x4C, 0x03, 0x35, 0xF3, 0x23, 0xB8, 0x5D, 0x6A, 0x92, 0xD5, 0x21, 0x44, 0x51, 0xC6, 0x7D,
   0x39, 0x83, 0xDC, 0xAA, 0x7C, 0x77, 0x56, 0x05, 0x1B, 0xA4, 0x15, 0x34, 0x1E, 0x1C, 0xF8, 0x52,
   0x20, 0x14, 0xE9, 0xBD, 0xDD, 0xE4, 0xA1, 0xE0, 0x8A, 0xF1, 0xD6, 0x7A, 0xBB, 0xE3, 0x40, 0x4F
};

//Substitution table 4
static const unsigned __int8 sbox4[256] =
{
   0x70, 0x2C, 0xB3, 0xC0, 0xE4, 0x57, 0xEA, 0xAE, 0x23, 0x6B, 0x45, 0xA5, 0xED, 0x4F, 0x1D, 0x92,
   0x86, 0xAF, 0x7C, 0x1F, 0x3E, 0xDC, 0x5E, 0x0B, 0xA6, 0x39, 0xD5, 0x5D, 0xD9, 0x5A, 0x51, 0x6C,
   0x8B, 0x9A, 0xFB, 0xB0, 0x74, 0x2B, 0xF0, 0x84, 0xDF, 0xCB, 0x34, 0x76, 0x6D, 0xA9, 0xD1, 0x04,
   0x14, 0x3A, 0xDE, 0x11, 0x32, 0x9C, 0x53, 0xF2, 0xFE, 0xCF, 0xC3, 0x7A, 0x24, 0xE8, 0x60, 0x69,
   0xAA, 0xA0, 0xA1, 0x62, 0x54, 0x1E, 0xE0, 0x64, 0x10, 0x00, 0xA3, 0x75, 0x8A, 0xE6, 0x09, 0xDD,
   0x87, 0x83, 0xCD, 0x90, 0x73, 0xF6, 0x9D, 0xBF, 0x52, 0xD8, 0xC8, 0xC6, 0x81, 0x6F, 0x13, 0x63,
   0xE9, 0xA7, 0x9F, 0xBC, 0x29, 0xF9, 0x2F, 0xB4, 0x78, 0x06, 0xE7, 0x71, 0xD4, 0xAB, 0x88, 0x8D,
   0x72, 0xB9, 0xF8, 0xAC, 0x36, 0x2A, 0x3C, 0xF1, 0x40, 0xD3, 0xBB, 0x43, 0x15, 0xAD, 0x77, 0x80,
   0x82, 0xEC, 0x27, 0xE5, 0x85, 0x35, 0x0C, 0x41, 0xEF, 0x93, 0x19, 0x21, 0x0E, 0x4E, 0x65, 0xBD,
   0xB8, 0x8F, 0xEB, 0xCE, 0x30, 0x5F, 0xC5, 0x1A, 0xE1, 0xCA, 0x47, 0x3D, 0x01, 0xD6, 0x56, 0x4D,
   0x0D, 0x66, 0xCC, 0x2D, 0x12, 0x20, 0xB1, 0x99, 0x4C, 0xC2, 0x7E, 0x05, 0xB7, 0x31, 0x17, 0xD7,
   0x58, 0x61, 0x1B, 0x1C, 0x0F, 0x16, 0x18, 0x22, 0x44, 0xB2, 0xB5, 0x91, 0x08, 0xA8, 0xFC, 0x50,
   0xD0, 0x7D, 0x89, 0x97, 0x5B, 0x95, 0xFF, 0xD2, 0xC4, 0x48, 0xF7, 0xDB, 0x03, 0xDA, 0x3F, 0x94,
   0x5C, 0x02, 0x4A, 0x33, 0x67, 0xF3, 0x7F, 0xE2, 0x9B, 0x26, 0x37, 0x3B, 0x96, 0x4B, 0xBE, 0x2E,
   0x79, 0x8C, 0x6E, 0x8E, 0xF5, 0xB6, 0xFD, 0x59, 0x98, 0x6A, 0x46, 0xBA, 0x25, 0x42, 0xA2, 0xFA,
   0x07, 0x55, 0xEE, 0x0A, 0x49, 0x68, 0x38, 0xA4, 0x28, 0x7B, 0xC9, 0xC1, 0xE3, 0xF4, 0xC7, 0x9E
};

// Rotate Left circular shift 32 bits
static unsigned __int32 ROL_32(unsigned __int32 x, unsigned __int32 n)
{
	return x << n | x >> (32 - n);
}

// Rotate Left circular shift 128 bits
void ROL_128(unsigned __int64* y, unsigned __int64* x, unsigned __int32 n)
{
	unsigned __int64 temp = x[0];
	y[0] = (x[0] << n) | (x[1] >> (64 - n));
	y[1] = (x[1] << n) | (temp >> (64 - n));
}

unsigned __int64 F(unsigned __int64 F_IN, unsigned __int64 KE)
{
	unsigned __int64 x;
	unsigned __int8 t1, t2, t3, t4, t5, t6, t7, t8;
	unsigned __int8 y1, y2, y3, y4, y5, y6, y7, y8;

	x = F_IN ^ KE;
	t1 = x >> 56;
	t2 = (unsigned __int8)(x >> 48);
	t3 = (unsigned __int8)(x >> 40);
	t4 = (unsigned __int8)(x >> 32);
	t5 = (unsigned __int8)(x >> 24);
	t6 = (unsigned __int8)(x >> 16);
	t7 = (unsigned __int8)(x >> 8);
	t8 = (unsigned __int8)x;
	t1 = sbox1[t1];
	t2 = sbox2[t2];
	t3 = sbox3[t3];
	t4 = sbox4[t4];
	t5 = sbox2[t5];
	t6 = sbox3[t6];
	t7 = sbox4[t7];
	t8 = sbox1[t8];
	y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
	y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
	y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
	y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
	y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
	y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
	y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
	y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
	return ((unsigned __int64)y1 << 56) | ((unsigned __int64)y2 << 48) | ((unsigned __int64)y3 << 40) | ((unsigned __int64)y4 << 32) |
		((unsigned __int64)y5 << 24) | ((unsigned __int64)y6 << 16) | ((unsigned __int64)y7 << 8) | y8;
}

unsigned __int64 FL(unsigned __int64 FL_IN, unsigned __int64 KE)
{
	unsigned __int32 x1, x2;
	unsigned __int32 k1, k2;
	x1 = FL_IN >> 32;
	x2 = (unsigned __int32)FL_IN;
	k1 = KE >> 32;
	k2 = (unsigned __int32)KE;
	x2 = x2 ^ ROL_32((x1 & k1), 1);
	x1 = x1 ^ (x2 | k2);
	return ((unsigned __int64)x1 << 32) | x2;
}

unsigned __int64 FLINV(unsigned __int64 FLINV_IN, unsigned __int64 KE)
{
	unsigned __int32 y1, y2;
	unsigned __int32 k1, k2;
	y1 = FLINV_IN >> 32;
	y2 = (unsigned __int32)FLINV_IN;
	k1 = KE >> 32;
	k2 = (unsigned __int32)KE;
	y1 = y1 ^ (y2 | k2);
	y2 = y2 ^ ROL_32((y1 & k1), 1);
	return ((unsigned __int64)y1 << 32) | y2;
}

void CAMELLIA_init(CamelliaContext* context, const unsigned __int64* key, unsigned __int16 keyLen)
{
	unsigned __int8 i;
	unsigned __int64 temp[2];

	unsigned __int64 KL[2];
	unsigned __int64 KR[2];
	unsigned __int64 KA[2];
	unsigned __int64 KB[2];
	unsigned __int64 D1;
	unsigned __int64 D2;

	// generate KL and KR
	if (keyLen == 128)
	{
		// 18 (nr rounds) / 6 (nr rounds required for each feistel iteration)
		context->feistelIterations = 3;
		context->nrSubkeys = 26;

		KL[0] = key[0];
		KL[1] = key[1];
		KR[0] = 0;
		KR[1] = 0;
	}
	else if (keyLen == 192 || keyLen == 256)
	{
		// 24 (nr rounds) / 6 (nr rounds required for each feistel iteration)
		context->feistelIterations = 4;
		context->nrSubkeys = 34;

		KL[0] = key[0];
		KL[1] = key[1];
		KR[0] = key[2];
		KR[1] = key[3];

		// special treatment for 192-bits key
		if (keyLen == 192)
		{
			KR[1] = ~key[2];
		}
	}
	else
	{
		//TODO create return status
		return;
	}

	// generate KA and KB
	D1 = KL[0] ^ KR[0];
	D2 = KL[1] ^ KR[1];
	D2 = D2 ^ F(D1, sigma[0]);
	D1 = D1 ^ F(D2, sigma[1]);
	D1 = D1 ^ KL[0];
	D2 = D2 ^ KL[1];
	D2 = D2 ^ F(D1, sigma[2]);
	D1 = D1 ^ F(D2, sigma[3]);
	KA[0] = D1;
	KA[1] = D2;
	D1 = KA[0] ^ KR[0];
	D2 = KA[1] ^ KR[1];
	D2 = D2 ^ F(D1, sigma[4]);
	D1 = D1 ^ F(D2, sigma[5]);
	KB[0] = D1;
	KB[1] = D2;

	// generate subkeys
	i = 0;
	if (keyLen == 128)
	{
		context->k[i++] = KL[0];
		context->k[i++] = KL[1];
		context->k[i++] = KA[0];
		context->k[i++] = KA[1];
		ROL_128(temp, KL, 15);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KA, 15);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KA, 30);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KL, 30); // 30 + 15 = 45 left circular shift
		ROL_128(temp, temp, 15);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KA, 30); // 30 + 15 = 45 left circular shift
		ROL_128(temp, temp, 15);
		context->k[i++] = temp[0];
		ROL_128(temp, KL, 30); // 30 + 30 = 45 left circular shift
		ROL_128(temp, temp, 30);
		context->k[i++] = temp[1];
		ROL_128(temp, KA, 30); // 30 + 30 = 45 left circular shift
		ROL_128(temp, temp, 30);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KL, 30); // 30 + 30 + 17 = 77 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 17);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KL, 30); // 30 + 30 + 30 + 4 = 94 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 4);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KA, 30); // 30 + 30 + 30 + 4 = 94 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 4);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KL, 30); // 30 + 30 + 30 + 21 = 111 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 21);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KA, 30); // 30 + 30 + 30 + 21 = 111 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 21);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
	}
	else
	{
		context->k[i++] = KL[0];
		context->k[i++] = KL[1];
		context->k[i++] = KB[0];
		context->k[i++] = KB[1];
		ROL_128(temp, KR, 15);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KA, 15);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KR, 30);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KB, 30);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KL, 30);
		ROL_128(temp, temp, 15);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KA, 30);
		ROL_128(temp, temp, 15);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KL, 30);
		ROL_128(temp, temp, 30);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KR, 30);
		ROL_128(temp, temp, 30);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KB, 30);
		ROL_128(temp, temp, 30);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KL, 30); // 60 + 17 = 77 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 17);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KA, 30); // 60 + 17 = 77 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 17);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KR, 30); // 60 + 34 = 94 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 34);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KA, 30); // 60 + 34 = 94 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 34);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KL, 30); // 60 + 51 = 111 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 21);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
		ROL_128(temp, KB, 30); // 60 + 51 = 111 left circular shift
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 30);
		ROL_128(temp, temp, 21);
		context->k[i++] = temp[0];
		context->k[i++] = temp[1];
	}
}

void CAMELLIA_encrypt(const CamelliaContext* context, const unsigned __int64* block, unsigned __int64* out)
{
	// D[0] is D1 and D[1] is D2
	unsigned __int64 D[2] = { block[0], block[1] };
	unsigned __int16 subkey = 0;
	unsigned __int16 dIndex;
	unsigned __int16 oppositeIndex;
	unsigned __int16 round;
	unsigned __int16 feistelIteration;

	D[0] ^= context->k[subkey++]; // Prewhitening
	D[1] ^= context->k[subkey++];

	// if 128-bits key then its 18 rounds divided into 3 feistel iterations
	// if 192/256-bits key then its 24 rounds and divided into 4 feistel iterations
	for (feistelIteration = 0; feistelIteration < context->feistelIterations; feistelIteration++)
	{
		// each feistel iteration is 6 rounds
		for (round = 1; round <= 6; round++)
		{
			// calculate index
			dIndex = round % 2;
			oppositeIndex = (~dIndex & 0x1);

			// D1 is calculated in even rounds and D2 in odd rounds
			D[dIndex] ^= F(D[oppositeIndex], context->k[subkey++]);
		}

		// do not insert FL and FLINV functions in last iteration
		if (feistelIteration != (context->feistelIterations - 1))
		{
			// between each feistel iteration FL and FLINV functions are inserted
			D[0] = FL(D[0], context->k[subkey++]);
			D[1] = FLINV(D[1], context->k[subkey++]);
		}
	}

	D[1] ^= context->k[subkey++]; // Postwhitening
	D[0] ^= context->k[subkey++];

	// copy cipher text to output
	out[0] = D[1];
	out[1] = D[0];
}

void CAMELLIA_decrypt(const CamelliaContext* context, const unsigned __int64* block, unsigned __int64* out)
{
	// D[0] is D1 and D[1] is D2
	unsigned __int64 D[2] = { block[0], block[1] };
	unsigned __int16 subkey = context->nrSubkeys - 1;
	unsigned __int16 dIndex;
	unsigned __int16 oppositeIndex;
	unsigned __int16 round;
	unsigned __int16 feistelIteration;

	// Prewhitening
	D[1] ^= context->k[subkey--];
	D[0] ^= context->k[subkey--];

	// if 128-bits key then its 18 rounds divided into 3 feistel iterations
	// if 192/256-bits key then its 24 rounds and divided into 4 feistel iterations
	for (feistelIteration = 0; feistelIteration < context->feistelIterations; feistelIteration++)
	{
		// each feistel iteration is 6 rounds
		for (round = 1; round <= 6; round++)
		{
			// calculate index
			dIndex = round % 2;
			oppositeIndex = (~dIndex & 0x1);

			// D1 is calculated in even rounds and D2 in odd rounds
			D[dIndex] ^= F(D[oppositeIndex], context->k[subkey--]);
		}

		// do not insert FL and FLINV functions in last iteration
		if (feistelIteration != (context->feistelIterations - 1))
		{
			// between each feistel iteration FL and FLINV functions are inserted
			D[0] = FL(D[0], context->k[subkey--]);
			D[1] = FLINV(D[1], context->k[subkey--]);
		}
	}

	// Postwhitening
	D[0] ^= context->k[subkey--];
	D[1] ^= context->k[subkey--];

	// copy cipher text to output
	out[0] = D[1];
	out[1] = D[0];
}

void CAMELLIA_main(void)
{
	CamelliaContext context;
	int i;
	unsigned __int64 key[4];
	unsigned __int64 text[2];
	unsigned __int64 cipherText[2];
	unsigned __int64 expectedCipherText[2];
	unsigned __int64 decryptedText[2];

	// test for 128-bits key

	// key 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
	key[0] = 0x0123456789abcdef;
	key[1] = 0xfedcba9876543210;

	// text 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
	text[0] = 0x0123456789abcdef;
	text[1] = 0xfedcba9876543210;

	// expected encrypted text 67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43
	expectedCipherText[0] = 0x6767313854966973;
	expectedCipherText[1] = 0x0857065648eabe43;

	CAMELLIA_init(&context, key, 128);

	CAMELLIA_encrypt(&context, text, cipherText);
	CAMELLIA_decrypt(&context, cipherText, decryptedText);

	printf("\nCAMELLIA 128-bits key \n\n");

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

	// key 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 00 11 22 33 44 55 66 77
	key[0] = 0x0123456789abcdef;
	key[1] = 0xfedcba9876543210;
	key[2] = 0x0011223344556677;

	// expected encrypted text b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9
	expectedCipherText[0] = 0xb4993401b3e996f8;
	expectedCipherText[1] = 0x4ee5cee7d79b09b9;

	CAMELLIA_init(&context, key, 192);

	CAMELLIA_encrypt(&context, text, cipherText);
	CAMELLIA_decrypt(&context, cipherText, decryptedText);

	printf("\nCAMELLIA 192-bits key \n\n");

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

	// key 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
	key[0] = 0x0123456789abcdef;
	key[1] = 0xfedcba9876543210;
	key[2] = 0x0011223344556677;
	key[3] = 0x8899aabbccddeeff;

	// expected encrypted text 9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09
	expectedCipherText[0] = 0x9acc237dff16d76c;
	expectedCipherText[1] = 0x20ef7c919e3a7509;

	CAMELLIA_init(&context, key, 256);

	CAMELLIA_encrypt(&context, text, cipherText);
	CAMELLIA_decrypt(&context, cipherText, decryptedText);

	printf("\nCAMELLIA 256-bits key \n\n");

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

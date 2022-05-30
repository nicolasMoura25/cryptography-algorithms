#include "CTRMode.h"
#include "algorithms/ARIA/ARIA.h"

void Select_Algorithm(CTRCounter* ctrCounter, enum Algorithm algorithm){
	switch (algorithm)
		{
		case ARIA_128 :
			ARIA_main(ctrCounter, 128);
			break;
		case ARIA_192 :
			ARIA_main(ctrCounter, 192);
			break;
		case ARIA_256 :
			ARIA_main(ctrCounter, 256);
			break;
		case CAMELLIA_128 :
			CAMELLIA_main(ctrCounter, 128);
			break;
		case CAMELLIA_192 :
			CAMELLIA_main(ctrCounter, 192);
			break;
		case CAMELLIA_256 :
			CAMELLIA_main(ctrCounter, 256);
			break;
		case NOEKEON_128 :
			NOEKEON_main(ctrCounter, 128);
			break;
		case SEED_128 :
			SEED_main(ctrCounter, 128);
			break;
		case SIMON_128 :
			SIMON_main(ctrCounter, 128);
			break;
		case SIMON_192 :
			SIMON_main(ctrCounter, 192);
			break;
		case SIMON_256 :
			SIMON_main(ctrCounter, 256);
			break;

		case SPECK_128 :
			SPECK_main(ctrCounter, 128);
			break;
		case SPECK_192 :
			SPECK_main(ctrCounter, 192);
			break;
		case SPECK_256 :
			SPECK_main(ctrCounter, 256);
			break;

		default:
			break;
		}
}



void CTRMode_main(CTRCounter ctrCounter, enum Algorithm algorithm){

    // ENCRYPT SIDE
	
    Select_Algorithm(&ctrCounter, algorithm);

	ctrCounter.cipherTemp[0] = ctrCounter.text[0] ^ ctrCounter.cipherText[0];
	ctrCounter.cipherTemp[1] = ctrCounter.text[1] ^ ctrCounter.cipherText[1];
	ctrCounter.cipherTemp[2] = ctrCounter.text[2] ^ ctrCounter.cipherText[2];
	ctrCounter.cipherTemp[3] = ctrCounter.text[3] ^ ctrCounter.cipherText[3];

	printf("\nCypher: \t\t");
	for (int i = 0; i < 4; i++)
	{
		printf("%08x ", ctrCounter.cipherTemp[i]);
	}

	
	// DECRYPT SIDE
	Select_Algorithm(&ctrCounter, algorithm);
	
	ctrCounter.cipherText[0] = ctrCounter.cipherTemp[0] ^ ctrCounter.cipherText[0];
	ctrCounter.cipherText[1] = ctrCounter.cipherTemp[1] ^ ctrCounter.cipherText[1];
	ctrCounter.cipherText[2] = ctrCounter.cipherTemp[2] ^ ctrCounter.cipherText[2];
	ctrCounter.cipherText[3] = ctrCounter.cipherTemp[3] ^ ctrCounter.cipherText[3];
	
	printf("\nDecrypt: \t\t");
	for (int i = 0; i < 4; i++)
	{
		printf("%08x ", ctrCounter.cipherText[i]);
	}		
	printf("\n\n");
}
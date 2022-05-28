#include "CTRMode.h"
#include "algorithms/ARIA/ARIA.h"

void CTRMode_main(CTRCounter ctrCounter){

    // ENCRYPT SIDE
    ctrCounter = ARIA_main(ctrCounter);
	
	 
	/* helpful on debug
	printf("Cypher EENCRYPT: \t\t\t\t\n");
	for (int i = 0; i < 4; i++)
	{
		printf("%08x \n", ctrCounter.cipherText[i]);
	}
	printf("\n");
	*/
		
	ctrCounter.cipherTemp[0] = ctrCounter.text[0] ^ ctrCounter.cipherText[0];
	ctrCounter.cipherTemp[1] = ctrCounter.text[1] ^ ctrCounter.cipherText[1];
	ctrCounter.cipherTemp[2] = ctrCounter.text[2] ^ ctrCounter.cipherText[2];
	ctrCounter.cipherTemp[3] = ctrCounter.text[3] ^ ctrCounter.cipherText[3];
	
	
	/* helpful on debug
	printf("ENCRYPT completed: \t\t\t\t\n");
	for (int i = 0; i < 4; i++)
	{
		printf("%08x ", ctrCounter.cipherTemp[i]);
	}
	printf("\n"); */
	
	
	// DECRYPT SIDE
	ctrCounter = ARIA_main(ctrCounter);
	
	/* helpful on debug
	printf("Cypher DECRYPT: \t\t\t\t\n");
	for (int i = 0; i < 4; i++)
	{
		printf("%08x \n", ctrCounter.cipherText[i]);
	}
	printf("\n");
	*/
	
	ctrCounter.cipherText[0] = ctrCounter.cipherTemp[0] ^ ctrCounter.cipherText[0];
	ctrCounter.cipherText[1] = ctrCounter.cipherTemp[1] ^ ctrCounter.cipherText[1];
	ctrCounter.cipherText[2] = ctrCounter.cipherTemp[2] ^ ctrCounter.cipherText[2];
	ctrCounter.cipherText[3] = ctrCounter.cipherTemp[3] ^ ctrCounter.cipherText[3];
	
	printf("\nResultado FINAL do CTR Após decriptografia: \t\t\t\t\n");
	for (int i = 0; i < 4; i++)
	{
		printf("%08x \n", ctrCounter.cipherText[i]);
	}	
}
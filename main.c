/* main.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 06/06/2021
 * 
 * This main is used to call the inner main functions of
 * each block cipher in order to validate them and visualize
 * the tests.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "algorithms/GOST/GOST.h"
#include "algorithms/ARIA/ARIA.h"
#include "algorithms/NOEKEON/NOEKEON.h"
#include "algorithms/IDEA/IDEA.h"
#include "algorithms/PRESENT/PRESENT.h"
#include "algorithms/CAMELLIA/CAMELLIA.h"
#include "algorithms/SPECK/SPECK.h"
#include "algorithms/SIMON/SIMON.h"
#include "algorithms/HIGHT/HIGHT.h"
#include "algorithms/SEED/SEED.h"
#include "CTR.h"
#include "CTRMode.h" 

int readText(uint32_t* textList,char* fileRead){

	uint32_t dataRead;
	FILE *file;
	int cont = 0;

	file = fopen(fileRead,"r");
	if(file == NULL){
		printf("Error in opening file\n");
		exit(1);
	}

	while(fscanf(file, "%x", &dataRead) != EOF){	
		textList[cont] = dataRead;
		cont++;
	}
	
	fclose(file);
	return cont;
}

void Call_CTR(enum Algorithm algorithm, int SIZE, char* fileKey){
	CTRCounter ctrCounter;
	Block128 newBlock;
	Block128 newNonce;

	int contText = 0;
	int contNonce = 0;	

	uint32_t textList[12];
	uint32_t nonceList[12];
	
	int numText = readText(&textList, "TextBlock.txt");
	int numNonce = readText(&nonceList, "NonceBlock.txt");
	int numKey = readText(&ctrCounter.Key, fileKey);

	for (int i = 0; i < numKey; i++)
		{			
			printf("%08x ", ctrCounter.Key[i]); 
		}

	do{

		printf("Text : \t\t\t"); 
		for (int i = 0; i < SIZE; i++)
		{			
			ctrCounter.text[i] = textList[contText];
			printf("%08x ", ctrCounter.text[i]); 
			contText++;
		}

		printf("\nNonce: \t\t\t"); 
		
		for (int i = 0; i < SIZE; i++)
		{			
			ctrCounter.ctrNonce[i] = nonceList[contNonce];
			printf("%08x ", ctrCounter.ctrNonce[i]);  
			contNonce++;
		}

		CTRMode_main(ctrCounter, algorithm);

	}while (contText < numText);	
}

int main()
{
	// TEXT 128-bits

	// ARIA 
	/*printf("\nARIA 128-bits :\n"); 
	Call_CTR(ARIA_128, 4, "Keys/ARIA_128.txt");	
	printf("\nARIA 192-bits :\n");
	Call_CTR(ARIA_192, 4, "Keys/ARIA_192.txt");
	printf("\nARIA 256-bits :\n");
	Call_CTR(ARIA_256, 4, "Keys/ARIA_256.txt");*/

	// CAMELLIA 
	/*printf("\nCAMELLIA 128-bits : \n");
	Call_CTR(CAMELLIA_128, 4, "Keys/CAMELLIA_128.txt");
	printf("\nCAMELLIA 192-bits : \n");
	Call_CTR(CAMELLIA_192, 4, "Keys/CAMELLIA_192.txt");
	printf("\nCAMELLIA 256-bits : \n");
	Call_CTR(CAMELLIA_256, 4, "Keys/CAMELLIA_256.txt");*/

	// NOEKEON
	/*printf("\nNOEKEON 128-bits :\n"); 
	Call_CTR(NOEKEON_128, 4, "Keys/NOEKEON_128.txt");*/

	// SEED
	/*printf("\nSEED 128-bits :\n"); 
	Call_CTR(SEED_128, 4, "Keys/SEED_128.txt");*/

	// SIMON 
	/*printf("\nSIMON 128-bits :\n"); 
	Call_CTR(SIMON_128, 4, "Keys/SIMON_128.txt");
	printf("\nSIMON 192-bits :\n");
	Call_CTR(SIMON_192, 4, "Keys/SIMON_192.txt");
	printf("\nSIMON 256-bits :\n");
	Call_CTR(SIMON_256, 4, "Keys/SIMON_256.txt");*/


	// SPECK 
	/*printf("\nSPECK 128-bits :\n"); 
	Call_CTR(SPECK_128, 4, "Keys/SPECK_128.txt");
	printf("\nSPECK 192-bits :\n");
	Call_CTR(SPECK_192, 4, "Keys/SPECK_192.txt");
	printf("\nSPECK 256-bits :\n");
	Call_CTR(SPECK_256, 4, "Keys/SPECK_256.txt");*/


	// TEXT 64-bits
	//printf("\nGOST 256-bits :\n");
	//Call_CTR(GOST_256, 2, "Keys/GOST_256.txt");
	
	printf("\nIDEIA 128-bits :\n");
	Call_CTR(IDEA_128, 2, "Keys/IDEA_128.txt");

	return 0;	



	// 64 Block Lenth	
	//HIGHT_main();
	//IDEA_main();
	//PRESENT_main();

}
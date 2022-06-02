/* main.h
*
 * Authors: Vinicius Borba da Rocha; Nicolas Moura
 * Created: 06/06/2021 - Initial Version
 * Updated: 21/05/2021 - CTR mode Implementation
 * 
 * This main is used to call the CTR mode and inner main functions of
 * each block cipher in order to validate them and visualize
 * the tests.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "CTRMode.h"
#include "algorithms/ARIA/ARIA.h"
#include "algorithms/CAMELLIA/CAMELLIA.h"
#include "algorithms/NOEKEON/NOEKEON.h"
#include "algorithms/SEED/SEED.h"
#include "algorithms/SIMON/SIMON.h"
#include "algorithms/SPECK/SPECK.h"
#include "algorithms/IDEA/IDEA.h"
#include "algorithms/PRESENT/PRESENT.h"
#include "algorithms/HIGHT/HIGHT.h"
#include "algorithms/GOST/GOST.h"

#define TEXT_SIZE_64 2
#define TEXT_SIZE_128 4

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

	int contText = 0;
	int contNonce = 0;	

	uint32_t textList[12];
	uint32_t nonceList[12];
	
	int numText = readText(&textList, "TextBlock.txt");
	readText(&nonceList, "NonceBlock.txt");
	readText(&ctrCounter.Key, fileKey);

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

		CTRMode_main(ctrCounter, algorithm, SIZE);

	}while (contText < numText);	
}

int main()
{
	// TEXT SIZE 128-bits

	printf("\n\t-----ARIA 128-bits :----- \n"); 
	Call_CTR(ARIA_128, TEXT_SIZE_128, "Keys/ARIA_128.txt");	
	printf("\n\t-----ARIA 192-bits :----- \n");
	Call_CTR(ARIA_192, TEXT_SIZE_128, "Keys/ARIA_192.txt");
	printf("\n\t-----ARIA 256-bits :----- \n");
	Call_CTR(ARIA_256, TEXT_SIZE_128, "Keys/ARIA_256.txt");

	printf("\n\t-----CAMELLIA 128-bits :----- \n");
	Call_CTR(CAMELLIA_128, TEXT_SIZE_128, "Keys/CAMELLIA_128.txt");
	printf("\n\t-----CAMELLIA 192-bits :----- \n");
	Call_CTR(CAMELLIA_192, TEXT_SIZE_128, "Keys/CAMELLIA_192.txt");
	printf("\n\t-----CAMELLIA 256-bits :----- \n");
	Call_CTR(CAMELLIA_256, TEXT_SIZE_128, "Keys/CAMELLIA_256.txt");


	printf("\n\t-----NOEKEON 128-bits :-----\n"); 
	Call_CTR(NOEKEON_128, TEXT_SIZE_128, "Keys/NOEKEON_128.txt");

	printf("\n\t-----SEED 128-bits :-----\n"); 
	Call_CTR(SEED_128, TEXT_SIZE_128, "Keys/SEED_128.txt");


	printf("\n\t-----SIMON 128-bits :-----\n"); 
	Call_CTR(SIMON_128, TEXT_SIZE_128, "Keys/SIMON_128.txt");
	printf("\n\t-----SIMON 192-bits :-----\n");
	Call_CTR(SIMON_192, TEXT_SIZE_128, "Keys/SIMON_192.txt");
	printf("\n\t-----SIMON 256-bits :-----\n");
	Call_CTR(SIMON_256, TEXT_SIZE_128, "Keys/SIMON_256.txt");


	printf("\n\t-----SPECK 128-bits :-----\n"); 
	Call_CTR(SPECK_128, TEXT_SIZE_128, "Keys/SPECK_128.txt");
	printf("\n\t-----SPECK 192-bits :-----\n");
	Call_CTR(SPECK_192, TEXT_SIZE_128, "Keys/SPECK_192.txt");
	printf("\n\t-----SPECK 256-bits :-----\n");
	Call_CTR(SPECK_256, TEXT_SIZE_128, "Keys/SPECK_256.txt");


	// TEXT SIZE 64-bits	
	
	printf("\n\t-----IDEA 128-bits :-----\n");
	Call_CTR(IDEA_128, TEXT_SIZE_64, "Keys/IDEA_128.txt");

	printf("\n\t-----PRESENT 80-bits :-----\n");
	Call_CTR(PRESENT_80, TEXT_SIZE_64, "Keys/PRESENT_128.txt");
	printf("\n\t-----PRESENT 128-bits :-----\n");
	Call_CTR(PRESENT_128, TEXT_SIZE_64, "Keys/PRESENT_128.txt");

	printf("\n\t-----HIGHT 128-bits :-----\n");
	Call_CTR(HIGHT_128, TEXT_SIZE_64, "Keys/HIGHT_128.txt");

	printf("\n\t-----GOST 256-bits :-----\n");
	Call_CTR(GOST_256, TEXT_SIZE_64, "Keys/GOST_256.txt");

	return 0;	
}

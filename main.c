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

void readText(int position, Block128* block128){

	uint32_t dataRead;
	FILE *file;
	int i = 0;
	int cont = 0;

	file = fopen("TextBlock.txt","r");
	if(file == NULL){
		printf("Error in opening file\n");
		exit(1);
	}
	
	while(fscanf(file, "%x", &dataRead) != EOF){
			
		if(cont >= (position-1)*4 && cont < position*4){
			block128->result[i] = dataRead;	
			i++;	
		}
		cont++;
		if(cont == position*4){
			fclose(file);
		}
	}
}

void readNonce(int position, Block128* block128){

	uint32_t NonceRead;
	FILE *file;
	int i = 0;
	int cont = 0;

	file = fopen("NonceBlock.txt","r");
	if(file == NULL){
		printf("Error in opening file\n");
		exit(1);
	}
	
	while(fscanf(file, "%x", &NonceRead) != EOF){
		
		if(cont >= (position-1)*4 && cont < position*4){
			block128->result[i] = NonceRead;
			i++;						
		}
		cont++;
		if(cont == position*4){
			fclose(file);
		}
	}
}

void Call_CTR(enum Algorithm algorithm){
	CTRCounter ctrCounter;
	Block128 newBlock;
	Block128 newNonce;
	int cont = 1;

		
	do{
		readText(cont, &newBlock);

		printf("Text : \t\t\t"); 
		for (int i = 0; i < 4; i++)
		{			
			ctrCounter.text[i] = newBlock.result[i];
			printf("%08x ", ctrCounter.text[i]); 
		}

		printf("\nNonce: \t\t\t"); 
		readNonce(cont, &newNonce);
		for (int i = 0; i < 4; i++)
		{			
			ctrCounter.ctrNonce[i] = newNonce.result[i];
			printf("%08x ", ctrCounter.ctrNonce[i]);  
		}

		CTRMode_main(ctrCounter, algorithm);

		cont++;
	}while (cont < 4);	
}

int main()
{
	// TEXT 128-bits

	// ARIA 
	printf("\nARIA 128-bits :\n"); 
	Call_CTR(ARIA_128);
	printf("\nARIA 192-bits :\n");
	Call_CTR(ARIA_192);
	printf("\nARIA 256-bits :\n");
	Call_CTR(ARIA_256);

	// CAMELLIA
	printf("\nCAMELLIA 128-bits : \n");
	Call_CTR(CAMELLIA_128);
	printf("\nCAMELLIA 192-bits : \n");
	Call_CTR(CAMELLIA_192);
	printf("\nCAMELLIA 256-bits : \n");
	Call_CTR(CAMELLIA_256);

	// NOEKEON
	printf("\nNOEKEON 128-bits :\n"); 
	Call_CTR(NOEKEON_128);

	// SEED
	printf("\nSEED 128-bits :\n"); 
	Call_CTR(SEED_128);

	// SIMON 
	printf("\nSIMON 128-bits :\n"); 
	Call_CTR(SIMON_128);
	printf("\nSIMON 192-bits :\n");
	Call_CTR(SIMON_192);
	printf("\nSIMON 256-bits :\n");
	Call_CTR(SIMON_256);


	// SPECK 
	printf("\nSPECK 128-bits :\n"); 
	Call_CTR(SPECK_128);
	printf("\nSPECK 192-bits :\n");
	Call_CTR(SPECK_192);
	printf("\nSPECK 256-bits :\n");
	Call_CTR(SPECK_256);
	

	
	return 0;	



	// 64 Block Lenth	
	//GOST_main();	
	//HIGHT_main();
	//IDEA_main();
	//PRESENT_main();

}
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

int main()
{
	CTRCounter ctrCounter;
	Block128 newBlock;
	Block128 newNonce;
	int cont = 1;
	int numLinhas = 8;
		
	do{
		readText(cont, &newBlock);

		printf("\nRead Text : \t\t\t\t\n"); // helpful on debug
		for (int i = 0; i < 4; i++)
		{			
			ctrCounter.text[i] = newBlock.result[i];
			printf("%08x \n", ctrCounter.text[i]); // helpful on debug
		}

		printf("\nRead Nonce: \t\t\t\t\n"); // helpful on debug
		readNonce(cont, &newNonce);
		for (int i = 0; i < 4; i++)
		{			
			ctrCounter.ctrNonce[i] = newNonce.result[i];
			printf("%08x \n", ctrCounter.ctrNonce[i]); // helpful on debug 
		}


		CTRMode_main(ctrCounter);

		cont++;
	}while (cont < 4);
	

	
	return 0;	

	// 64 Block Lenth	
	//GOST_main();	
	//HIGHT_main();
	//IDEA_main();
	//PRESENT_main();
	

	// 128 Block lenth
	
	//CAMELLIA_main();
	//NOEKEON_main();		
	//SEED_main();
	//SIMON_main();
	//SPECK_main();

}

void readText(int position, Block128* block128){

	uint32_t dataRead;
	FILE *file;
	int cont = 0;
	int i =0;

	file = fopen("TextBlock.txt","r");
	if(file == NULL){
		printf("Error in opening file\n");
		exit(1);
	}
	
	while(fscanf(file, "%x", &dataRead) != EOF){
			
		if(cont >= (position-1)*4 && cont < position*4){
			//printf("Text: %x  \t posição: %d\n",dataRead, cont); // debub
			block128->result[i] = dataRead;	
			i++;	
		}
		cont++;
		if(cont == position*4){
			fclose(file);
			return 0;
		}
	}
}

void readNonce(int position, Block128* block128){

	uint32_t NonceRead;
	FILE *file;
	int i =0;
	int cont = 0;

	file = fopen("NonceBlock.txt","r");
	if(file == NULL){
		printf("Error in opening file\n");
		exit(1);
	}
	
	while(fscanf(file, "%x", &NonceRead) != EOF){
		
		if(cont >= (position-1)*4 && cont < position*4){
			//printf("Nonce: %x\n",dataRead); // debub
			block128->result[i] = NonceRead;
			i++;						
		}
		cont++;
		if(cont == position*4){
			fclose(file);
			return 0;
		}
	}
}
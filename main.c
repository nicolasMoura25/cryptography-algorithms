#include <stdio.h>
#include "algorithms/GOST/GOST.h"

int main()
{
	unsigned __int32 key[8];
	for (int i = 0; i < 8; i++)
	{
		key[i] = i;
	}

	unsigned __int64 ivalue = 118105110105;

	unsigned __int64 encrypted = encrypt(ivalue, key);
	unsigned __int64 decrypted = decrypt(encrypted, key);

	printf("unencrypted txt %llu \n", ivalue);
	printf("encrypted txt: %llu \n", encrypted);
	printf("decrypted txt %llu \n", decrypted);

	return 0;
}
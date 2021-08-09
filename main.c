#include <stdio.h>
#include "algorithms/GOST/GOST.h"
#include "algorithms/ARIA/ARIA.h"
#include "algorithms/NOEKEON/NOEKEON.h"
#include "algorithms/IDEA/IDEA.h"
#include "algorithms/PRESENT/PRESENT.h"
#include "algorithms/CAMELLIA/CAMELLIA.h"
#include "algorithms/SPECK/SPECK.h"

int main()
{
	//GOST_main();
	//ARIA_main();
	//NOEKEON_main();
	//IDEA_main();
	//PRESENT_main();
	//CAMELLIA_main();
	SPECK_main();

	return 0;
}
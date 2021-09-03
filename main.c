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

int main()
{
	GOST_main();
	ARIA_main();
	NOEKEON_main();
	IDEA_main();
	PRESENT_main();
	CAMELLIA_main();
	SPECK_main();
	SIMON_main();
	HIGHT_main();
	SEED_main();

	return 0;
}
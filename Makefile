all: app

app: ARIA.o CAMELLIA.o GOST.o HIGHT.o IDEA.o NOEKEON.o PRESENT.o SEED.o SIMON.o SPECK.o main.o CTRMode.o
	gcc -Wall -o app ARIA.o CAMELLIA.o GOST.o HIGHT.o IDEA.o NOEKEON.o PRESENT.o SEED.o SIMON.o SPECK.o main.o CTRMode.o
	
ARIA.o: algorithms/ARIA/ARIA.c
	gcc -c -Wall algorithms/ARIA/ARIA.c
	
CAMELLIA.o: algorithms/CAMELLIA/CAMELLIA.c
	gcc -c -Wall algorithms/CAMELLIA/CAMELLIA.c
	
GOST.o: algorithms/GOST/GOST.c
	gcc -c -Wall algorithms/GOST/GOST.c
	
HIGHT.o: algorithms/HIGHT/HIGHT.c
	gcc -c -Wall algorithms/HIGHT/HIGHT.c
	
IDEA.o: algorithms/IDEA/IDEA.c
	gcc -c -Wall algorithms/IDEA/IDEA.c
	
NOEKEON.o: algorithms/NOEKEON/NOEKEON.c
	gcc -c -Wall algorithms/NOEKEON/NOEKEON.c
	
PRESENT.o: algorithms/PRESENT/PRESENT.c
	gcc -c -Wall algorithms/PRESENT/PRESENT.c
	
SEED.o: algorithms/SEED/SEED.c
	gcc -c -Wall algorithms/SEED/SEED.c
	
SIMON.o: algorithms/SIMON/SIMON.c
	gcc -c -Wall algorithms/SIMON/SIMON.c
	
SPECK.o: algorithms/SPECK/SPECK.c
	gcc -c -Wall algorithms/SPECK/SPECK.c

main.o: main.c
	gcc -c -Wall main.c

CTR.o: CTRMode.c
	gcc -c -wall CTRMode.c

clean:
	rm -f *.o
	rm -f app